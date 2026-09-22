//! Configuration for the proof orchestrator.

use std::{fmt, num::NonZeroUsize, path::PathBuf, time::Duration};

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use strata_asm_common::SpecId;
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

    /// Which proof backend to construct at startup, plus its configuration.
    ///
    /// Required in both modes: a follower still proves locally when its peer
    /// is unavailable or lagging.
    pub backend: BackendConfig,

    /// Expected ASM artifact identity, independently supplied from the execution registry.
    pub asm_predicate: PredicateKey,

    /// Additional ASM releases available to this prover; never selects activation.
    #[serde(default)]
    pub asm_artifacts: Vec<AsmArtifactConfig>,
    /// Maximum cached ASM hosts. Active backend operations may retain host clones.
    #[serde(default = "default_host_capacity")]
    pub max_loaded_asm_hosts: NonZeroUsize,
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

fn default_host_capacity() -> NonZeroUsize {
    NonZeroUsize::new(1).expect("one is nonzero")
}

/// Operator-declared program identity and its artifact source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsmArtifactConfig {
    pub spec_id: SpecId,
    pub predicate: PredicateKey,
    pub source: AsmArtifactSource,
}

/// Location or native signing identity used to construct an ASM host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AsmArtifactSource {
    Sp1 {
        elf_path: PathBuf,
    },
    Native {
        #[serde(with = "hex_signing_key")]
        signing_key: SigningKey,
    },
}

// Rust's Debug derive cannot redact fields; format manually to keep signing keys out of logs.
impl fmt::Debug for AsmArtifactSource {
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

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "sp1"))]
    use {
        crate::{
            AsmHostLoader, AsmProofHost, ProofBackend, ProofHost, ProverError, ProverResult,
            load_spec_host,
        },
        strata_asm_common::AsmSpec,
        strata_asm_spec::StrataAsmSpec,
    };

    use super::*;

    const BASE: &str = r#"
        tick_interval = { secs = 1, nanos = 0 }
        max_concurrent_proofs = 4
        proof_db_path = "/tmp/proof-db"
        asm_predicate = "Bip340Schnorr:1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"

        [backend]
        kind = "native"
        asm_schnorr_signing_key = "0101010101010101010101010101010101010101010101010101010101010101"
        moho_schnorr_signing_key = "0202020202020202020202020202020202020202020202020202020202020202"
    "#;

    #[cfg(not(feature = "sp1"))]
    #[derive(Debug)]
    struct TestLoader;

    #[cfg(not(feature = "sp1"))]
    impl AsmHostLoader for TestLoader {
        type Host = ProofHost;

        fn validate_spec(&self, spec_id: SpecId) -> ProverResult<()> {
            if spec_id != StrataAsmSpec::ID {
                return Err(ProverError::BackendUnavailable("unsupported test spec"));
            }
            Ok(())
        }

        async fn load(
            &self,
            artifact: &AsmArtifactConfig,
        ) -> ProverResult<AsmProofHost<Self::Host>> {
            load_spec_host(&artifact.source, StrataAsmSpec).await
        }
    }

    #[cfg(not(feature = "sp1"))]
    #[tokio::test]
    async fn native_fixture_matches_independent_expected_predicate() {
        let mut config: OrchestratorConfig = toml::from_str(BASE).unwrap();
        let mut backend = ProofBackend::new(&config, StrataAsmSpec::ID, TestLoader)
            .await
            .unwrap();
        backend.asm_host.load(&config.asm_predicate).await.unwrap();

        // The registry must check the loaded key, not just trust configured metadata.
        config.asm_predicate = PredicateKey::always_accept();
        let mut backend = ProofBackend::new(&config, StrataAsmSpec::ID, TestLoader)
            .await
            .unwrap();
        assert!(matches!(
            backend.asm_host.load(&config.asm_predicate).await,
            Err(ProverError::AsmArtifactMismatch { .. })
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
