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

    /// Backend-specific configuration. Required under `sp1`; defaults to
    /// empty under native builds (until per-mode fields are added there).
    #[cfg_attr(not(feature = "sp1"), serde(default))]
    pub backend: BackendConfig,
}

/// Backend-specific orchestrator configuration.
///
/// The shape varies with the active proof backend (`sp1` vs native), so the
/// struct is cfg-gated to carry only the fields the active backend needs.
#[cfg(feature = "sp1")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackendConfig {
    /// Directory containing the SP1 guest ELFs (`asm.elf`, `moho.elf`).
    pub elfs_dir: PathBuf,
}

#[cfg(not(feature = "sp1"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct BackendConfig {
    // Future: pub schnorr_signing_key: SigningKey,
}
