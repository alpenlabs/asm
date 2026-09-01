//! Configuration for the proof orchestrator.

use std::{fmt, path::PathBuf, time::Duration};

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use strata_asm_common::{AsmSpecId, GuestArtifactId};

/// Configuration for the proof orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Interval between orchestrator ticks.
    pub tick_interval: Duration,

    /// Maximum number of concurrent proof jobs in flight.
    pub max_concurrent_proofs: usize,

    /// Path to the proof database (SledProofDb).
    pub proof_db_path: PathBuf,

    /// Which proof backend to construct at startup, plus its configuration.
    ///
    /// Required in both modes: a follower still proves locally when its peer
    /// is unavailable or lagging.
    pub backend: BackendConfig,

    /// How the worker obtains proofs. Omit for [`ProverMode::Generator`].
    #[serde(default)]
    pub mode: ProverMode,
}

/// How the prover worker obtains proofs.
///
/// Tagged with `kind`, mirroring [`BackendConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProverMode {
    /// Generate every proof locally by submitting jobs to the configured
    /// proving backend. This is the default.
    #[default]
    Generator,

    /// Fetch completed proofs from a peer asm-runner's proof RPC instead of
    /// generating them, falling back to local generation when the peer is
    /// unreachable or its proven frontier lags too far behind.
    Follower(FollowerConfig),
}

/// Tuning for [`ProverMode::Follower`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowerConfig {
    /// URL of the peer asm-runner's RPC server to fetch proofs from.
    pub peer_url: String,

    /// Maximum number of L1 blocks the peer's proven frontier may trail this
    /// node's committed tip before the worker falls back to generating proofs
    /// locally.
    #[serde(default = "default_max_lag")]
    pub max_lag: u32,

    /// Consecutive failed peer status probes (one per tick) tolerated before
    /// falling back to generating proofs locally.
    #[serde(default = "default_max_peer_failures")]
    pub max_peer_failures: u32,
}

fn default_max_lag() -> u32 {
    12
}

fn default_max_peer_failures() -> u32 {
    3
}

/// One release-qualified SP1 guest and its local files.
///
/// The operator selects an immutable artifact identity, never a semantic spec.
/// Startup resolves the identity through the compiled release registry, hashes
/// both files, parses the VK, derives the ELF predicate, and rejects any
/// disagreement before a proof can be scheduled.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsmGuestConfig {
    /// Qualified artifact statement to load.
    pub artifact_id: GuestArtifactId,

    /// Path to the guest ELF.
    pub elf_path: PathBuf,

    /// Path to the JSON-encoded predicate/VK asset published with the ELF.
    pub vk_path: PathBuf,
}

/// One native ASM proving key and the specification it stands for.
///
/// See [`BackendConfig::NativeDevelopment`] for why a key fixes a predicate
/// identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct NativeAsmGuestConfig {
    /// The specification this key's host executes, as its numeric id.
    pub spec: AsmSpecId,

    /// BIP-340 Schnorr signing key whose verifying key becomes this host's
    /// predicate identity.
    #[serde(with = "hex_signing_key")]
    pub schnorr_signing_key: SigningKey,
}

impl fmt::Debug for NativeAsmGuestConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeAsmGuestConfig")
            .field("spec", &self.spec)
            .field("schnorr_signing_key", &"<redacted>")
            .finish()
    }
}

/// Backend-specific orchestrator configuration.
///
/// Tagged with `kind` so the same config schema is valid regardless of
/// which features the binary was built with. If the selected variant does
/// not match the build (e.g. `sp1` requested in a binary built without the
/// `sp1` feature), [`ProofBackend::new`](crate::ProofBackend::new) surfaces a
/// startup error.
///
/// The ASM side is a *list*: one entry per specification this node can prove.
/// Which entry proves a given block is decided per block, by the predicate the
/// parent handed over, so a node that spans an upgrade boundary needs the
/// artifacts for both sides of it. The Moho side stays singular — the recursive
/// program is specification-independent.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendConfig {
    /// SP1 backend. Loads each ASM guest ELF, and the Moho guest ELF, from
    /// explicit paths at startup.
    Sp1 {
        asm_guests: Vec<AsmGuestConfig>,
        moho_guest: AsmGuestConfig,
    },

    /// Native (in-process) backend. Each signing key fixes the predicate
    /// identity of its host: a native host's verifying key (derived from the
    /// configured signing key) is what `resolve_predicate` packs into the
    /// `PredicateKey`. Keys are parsed and validated as BIP-340 Schnorr
    /// signing keys at config load, so an invalid key fails startup rather
    /// than later in the proving path.
    NativeDevelopment {
        asm_guests: Vec<NativeAsmGuestConfig>,
        #[serde(with = "hex_signing_key")]
        moho_schnorr_signing_key: SigningKey,
    },
}

impl fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sp1 {
                asm_guests,
                moho_guest,
            } => f
                .debug_struct("Sp1")
                .field("asm_guests", asm_guests)
                .field("moho_guest", moho_guest)
                .finish(),
            Self::NativeDevelopment { asm_guests, .. } => f
                .debug_struct("NativeDevelopment")
                .field("asm_guests", asm_guests)
                .field("moho_schnorr_signing_key", &"<redacted>")
                .finish(),
        }
    }
}

impl BackendConfig {
    /// Reports whether this backend bypasses cryptographic release artifacts.
    /// The runner permits it only for regtest development chains.
    pub const fn is_unqualified_development(&self) -> bool {
        matches!(self, Self::NativeDevelopment { .. })
    }
}

mod hex_signing_key {
    use k256::schnorr::SigningKey;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(key: &SigningKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SigningKey, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        SigningKey::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
        tick_interval = { secs = 1, nanos = 0 }
        max_concurrent_proofs = 4
        proof_db_path = "/tmp/proof-db"

        [backend]
        kind = "native_development"
        moho_schnorr_signing_key = "0202020202020202020202020202020202020202020202020202020202020202"

        [[backend.asm_guests]]
        spec = 1
        schnorr_signing_key = "0101010101010101010101010101010101010101010101010101010101010101"
    "#;

    // Pre-existing configs carry no `[mode]` table and must keep parsing as
    // generator mode.
    #[test]
    fn mode_defaults_to_generator() {
        let config: OrchestratorConfig = toml::from_str(BASE).expect("should parse");
        assert!(matches!(config.mode, ProverMode::Generator));
    }

    #[test]
    fn follower_mode_parses_with_defaults() {
        let src =
            format!("{BASE}\n[mode]\nkind = \"follower\"\npeer_url = \"http://127.0.0.1:12400\"\n");
        let config: OrchestratorConfig = toml::from_str(&src).expect("should parse");
        let ProverMode::Follower(follower) = config.mode else {
            panic!("expected follower mode");
        };
        assert_eq!(follower.peer_url, "http://127.0.0.1:12400");
        assert_eq!(follower.max_lag, default_max_lag());
        assert_eq!(follower.max_peer_failures, default_max_peer_failures());
    }

    #[test]
    fn follower_mode_parses_explicit_thresholds() {
        let src = format!(
            "{BASE}\n[mode]\nkind = \"follower\"\npeer_url = \"http://127.0.0.1:12400\"\nmax_lag = 100\nmax_peer_failures = 5\n"
        );
        let config: OrchestratorConfig = toml::from_str(&src).expect("should parse");
        let ProverMode::Follower(follower) = config.mode else {
            panic!("expected follower mode");
        };
        assert_eq!(follower.max_lag, 100);
        assert_eq!(follower.max_peer_failures, 5);
    }

    /// A node spanning an upgrade boundary selects immutable artifact IDs; it
    /// cannot relabel an ELF with an operator-provided semantic specification.
    #[test]
    fn several_asm_guests_parse_with_qualified_artifact_ids() {
        let src = r#"
            tick_interval = { secs = 1, nanos = 0 }
            max_concurrent_proofs = 4
            proof_db_path = "/tmp/proof-db"

            [backend]
            kind = "sp1"

            [backend.moho_guest]
            artifact_id = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            elf_path = "/elfs/moho.elf"
            vk_path = "/elfs/moho-vk.json"

            [[backend.asm_guests]]
            artifact_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            elf_path = "/elfs/asm-v0.elf"
            vk_path = "/elfs/asm-v0-vk.json"

            [[backend.asm_guests]]
            artifact_id = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            elf_path = "/elfs/asm.elf"
            vk_path = "/elfs/asm-vk.json"
        "#;

        let config: OrchestratorConfig = toml::from_str(src).expect("should parse");
        let BackendConfig::Sp1 { asm_guests, .. } = config.backend else {
            panic!("expected sp1 backend");
        };
        assert_eq!(asm_guests.len(), 2);
        assert_eq!(asm_guests[0].artifact_id, GuestArtifactId::new([0x11; 32]));
        assert_eq!(asm_guests[0].elf_path, PathBuf::from("/elfs/asm-v0.elf"));
        assert_eq!(asm_guests[1].artifact_id, GuestArtifactId::new([0x22; 32]));
        assert_eq!(asm_guests[1].elf_path, PathBuf::from("/elfs/asm.elf"));
    }

    /// The functional tests generate this config from Python dataclasses, and a
    /// TOML writer may render a list of tables either as an array of tables or as
    /// an inline array of inline tables. Both must parse, so the emitter's choice
    /// of style cannot break the runner.
    #[test]
    fn asm_guests_parse_in_either_toml_style() {
        let inline = r#"
            tick_interval = { secs = 1, nanos = 0 }
            max_concurrent_proofs = 4
            proof_db_path = "/tmp/proof-db"

            [backend]
            kind = "sp1"
            asm_guests = [
              { artifact_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111", elf_path = "/elfs/asm-v0.elf", vk_path = "/elfs/asm-v0-vk.json" },
              { artifact_id = "sha256:2222222222222222222222222222222222222222222222222222222222222222", elf_path = "/elfs/asm.elf", vk_path = "/elfs/asm-vk.json" },
            ]

            [backend.moho_guest]
            artifact_id = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            elf_path = "/elfs/moho.elf"
            vk_path = "/elfs/moho-vk.json"
        "#;

        let config: OrchestratorConfig = toml::from_str(inline).expect("should parse");
        let BackendConfig::Sp1 { asm_guests, .. } = config.backend else {
            panic!("expected sp1 backend");
        };
        assert_eq!(
            asm_guests
                .iter()
                .map(|guest| (guest.artifact_id, guest.elf_path.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    GuestArtifactId::new([0x11; 32]),
                    PathBuf::from("/elfs/asm-v0.elf")
                ),
                (
                    GuestArtifactId::new([0x22; 32]),
                    PathBuf::from("/elfs/asm.elf")
                ),
            ],
        );
    }

    /// The removed `spec` field is rejected, not silently ignored. Otherwise an
    /// old config would appear to keep its label while startup ignored it.
    #[test]
    fn operator_provided_specification_label_fails_to_parse() {
        let src = r#"
            tick_interval = { secs = 1, nanos = 0 }
            max_concurrent_proofs = 4
            proof_db_path = "/tmp/proof-db"

            [backend]
            kind = "sp1"

            [backend.moho_guest]
            artifact_id = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            elf_path = "/elfs/moho.elf"
            vk_path = "/elfs/moho-vk.json"

            [[backend.asm_guests]]
            spec = 99
            artifact_id = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            elf_path = "/elfs/asm-v99.elf"
            vk_path = "/elfs/asm-v99-vk.json"
        "#;

        assert!(toml::from_str::<OrchestratorConfig>(src).is_err());
    }

    /// Secrets must not reach a log through the debug formatter.
    #[test]
    fn native_keys_are_redacted_in_debug_output() {
        let config: OrchestratorConfig = toml::from_str(BASE).expect("should parse");
        let rendered = format!("{:?}", config.backend);

        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("010101"), "{rendered}");
        assert!(!rendered.contains("020202"), "{rendered}");
    }
}
