//! Configuration for the proof orchestrator.

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

/// Configuration for the proof orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OrchestratorConfig {
    /// Interval between orchestrator ticks.
    pub tick_interval: Duration,

    /// Maximum number of concurrent proof jobs in flight.
    pub max_concurrent_proofs: usize,

    /// Path to the proof database (SledProofDb).
    pub proof_db_path: PathBuf,

    /// Which proof backend to construct at startup, plus its configuration.
    pub backend: BackendConfig,
}

/// Backend-specific orchestrator configuration.
///
/// Tagged with `kind` so the same config schema is valid regardless of
/// which features the binary was built with. If the selected variant does
/// not match the build (e.g. `sp1` requested in a binary built without the
/// `sp1` feature), [`crate::prover::backend::ProofBackend::new`] surfaces a
/// startup error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum BackendConfig {
    /// SP1 backend. ELFs at `<elfs_dir>/{asm,moho}.elf` are loaded at startup.
    Sp1 { elfs_dir: PathBuf },

    /// Native (in-process) backend. The signing key authenticates proofs
    /// from this host; parsed eagerly so config errors surface at startup.
    Native {
        #[serde(with = "hex_bytes")]
        schnorr_signing_key: [u8; 32],
    },
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom(format!("expected 32 bytes, got {}", bytes.len())))
    }
}
