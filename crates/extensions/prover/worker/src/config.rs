//! Configuration for the proof orchestrator.

use std::{fmt, path::PathBuf, time::Duration};

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};

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

/// Backend-specific orchestrator configuration.
///
/// Tagged with `kind` so the same config schema is valid regardless of
/// which features the binary was built with. If the selected variant does
/// not match the build (e.g. `sp1` requested in a binary built without the
/// `sp1` feature), [`ProofBackend::new`](crate::ProofBackend::new) surfaces a
/// startup error.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[expect(
    clippy::large_enum_variant,
    reason = "BackendConfig is parsed once at startup; boxing a SigningKey to save a few bytes on a singleton value is not worth the indirection"
)]
pub enum BackendConfig {
    /// SP1 backend. Loads the ASM and Moho guest ELFs from explicit paths at startup.
    Sp1 {
        asm_elf_path: PathBuf,
        moho_elf_path: PathBuf,
    },

    /// Native (in-process) backend. Each signing key fixes the predicate
    /// identity of its host: a native host's verifying key (derived from the
    /// configured signing key) is what `resolve_predicate` packs into the
    /// `PredicateKey`. Keys are parsed and validated as BIP-340 Schnorr
    /// signing keys at config load, so an invalid key fails startup rather
    /// than later in the proving path.
    Native {
        #[serde(with = "hex_signing_key")]
        asm_schnorr_signing_key: SigningKey,
        #[serde(with = "hex_signing_key")]
        moho_schnorr_signing_key: SigningKey,
    },
}

impl fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sp1 {
                asm_elf_path,
                moho_elf_path,
            } => f
                .debug_struct("Sp1")
                .field("asm_elf_path", asm_elf_path)
                .field("moho_elf_path", moho_elf_path)
                .finish(),
            Self::Native { .. } => f
                .debug_struct("Native")
                .field("asm_schnorr_signing_key", &"<redacted>")
                .field("moho_schnorr_signing_key", &"<redacted>")
                .finish(),
        }
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
        kind = "native"
        asm_schnorr_signing_key = "0101010101010101010101010101010101010101010101010101010101010101"
        moho_schnorr_signing_key = "0202020202020202020202020202020202020202020202020202020202020202"
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
}
