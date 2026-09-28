//! Configuration for the proof orchestrator.

use std::{fmt, path::PathBuf, time::Duration};

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use strata_predicate::PredicateKey;

/// Configuration for the proof orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Interval between orchestrator ticks.
    pub tick_interval: Duration,

    /// Maximum number of concurrent proof jobs in flight.
    pub max_concurrent_proofs: usize,

    /// Path to the proof database (SledProofDb).
    pub proof_db_path: PathBuf,

    /// Source of the Moho recursive proof program.
    ///
    /// Required in both modes: a follower still proves locally when its peer
    /// is unavailable or lagging.
    pub moho: ArtifactSource,

    /// Every ASM release this prover can prove.
    ///
    /// Each entry is loaded and checked against its predicate at startup, so a
    /// wrong ELF or key fails before the worker runs. The spec each predicate
    /// implements comes from the execution registry, not from this list.
    pub asm_artifacts: Vec<AsmArtifactConfig>,

    /// How the worker obtains proofs. Omit for [`ProverMode::Generator`].
    #[serde(default)]
    pub mode: ProverMode,
}

/// How the prover worker obtains proofs.
///
/// Tagged with `kind`, mirroring [`ArtifactSource`].
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

/// An ASM release this prover can prove and where to load it from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmArtifactConfig {
    /// Predicate the loaded host must resolve to.
    pub predicate: PredicateKey,

    /// Where the program's host is constructed from.
    pub source: ArtifactSource,
}

/// Location or native signing identity used to construct a proof host.
///
/// Tagged with `kind` so the same config schema is valid regardless of which
/// features the binary was built with. A source that does not match the build
/// (e.g. `sp1` in a binary built without the `sp1` feature) fails at startup
/// when its host is loaded.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactSource {
    /// SP1 guest ELF loaded from an explicit path.
    Sp1 { elf_path: PathBuf },

    /// Native (in-process) execution. The verifying key derived from this
    /// signing key is what `resolve_predicate` packs into the host's
    /// [`PredicateKey`]. Keys are parsed and validated as BIP-340 Schnorr
    /// signing keys at config load, so an invalid key fails startup rather
    /// than later in the proving path.
    Native {
        #[serde(with = "hex_signing_key")]
        signing_key: SigningKey,
    },
}

// Rust's Debug derive cannot redact fields; format manually to keep signing keys out of logs.
impl fmt::Debug for ArtifactSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sp1 { elf_path } => f.debug_struct("Sp1").field("elf_path", elf_path).finish(),
            Self::Native { .. } => f
                .debug_struct("Native")
                .field("signing_key", &"<redacted>")
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
    #[cfg(not(feature = "sp1"))]
    use {
        crate::{ProofBackend, ProverError, load_spec_host},
        strata_asm_spec::StrataAsmSpec,
    };

    use super::*;

    const BASE: &str = r#"
        tick_interval = { secs = 1, nanos = 0 }
        max_concurrent_proofs = 4
        proof_db_path = "/tmp/proof-db"

        [moho]
        kind = "native"
        signing_key = "0202020202020202020202020202020202020202020202020202020202020202"

        [[asm_artifacts]]
        predicate = "Bip340Schnorr:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"

        [asm_artifacts.source]
        kind = "native"
        signing_key = "0101010101010101010101010101010101010101010101010101010101010101"
    "#;

    #[cfg(not(feature = "sp1"))]
    #[tokio::test]
    async fn native_artifact_must_match_its_configured_predicate() {
        let config: OrchestratorConfig = toml::from_str(BASE).unwrap();
        let mut artifact = config.asm_artifacts[0].clone();
        let host = load_spec_host(&artifact, StrataAsmSpec).await.unwrap();
        assert_eq!(host.descriptor().predicate(), &artifact.predicate);
        let backend = ProofBackend::new(&config.moho, vec![host]).await.unwrap();
        backend.asm_hosts.get(&artifact.predicate).unwrap();

        // Loading must check the derived key, not just trust configured metadata.
        artifact.predicate = PredicateKey::always_accept();
        assert!(matches!(
            load_spec_host(&artifact, StrataAsmSpec).await,
            Err(ProverError::AsmArtifactMismatch { .. })
        ));
    }

    #[test]
    fn artifact_list_is_required() {
        let src = BASE
            .split("[[asm_artifacts]]")
            .next()
            .expect("split yields at least one piece");
        let err = toml::from_str::<OrchestratorConfig>(src).unwrap_err();
        assert!(err.message().contains("asm_artifacts"), "{err}");
    }

    #[test]
    fn artifact_sources_parse() {
        let config: OrchestratorConfig = toml::from_str(BASE).expect("should parse");
        assert!(matches!(config.moho, ArtifactSource::Native { .. }));
        assert_eq!(config.asm_artifacts.len(), 1);
        assert!(matches!(
            config.asm_artifacts[0].source,
            ArtifactSource::Native { .. }
        ));
    }

    // Configs may omit the `[mode]` table and must keep parsing as
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
