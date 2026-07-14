use bitcoin::Network;
use strata_btc_types::BitcoinTxid;
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_service::ServiceError;
use thiserror::Error;

/// Return type for worker messages.
pub type WorkerResult<T> = Result<T, WorkerError>;

/// The specific way a configured anchor disagrees with the L1 chain.
///
/// Produced at startup by the worker's anchor validation and wrapped by
/// [`WorkerError::AnchorMismatch`]. Each variant carries both the value the
/// anchor declared and the value the L1 source reports.
#[derive(Debug, Error)]
pub enum AnchorMismatch {
    /// The anchor's network differs from the backing L1 source.
    #[error("network: anchor declares {anchor:?}, L1 source reports {l1:?}")]
    Network { anchor: Network, l1: Network },

    /// The anchor commits to a different block than the one at its height on
    /// the active chain.
    #[error("block at height {height}: anchor commits to {anchor:?}, L1 has {l1:?}")]
    Block {
        height: u64,
        anchor: L1BlockId,
        l1: L1BlockId,
    },

    /// The anchor's epoch-start timestamp differs from the timestamp of the
    /// first block of its current difficulty-adjustment epoch.
    #[error(
        "epoch start timestamp: anchor declares {anchor}, L1 epoch start (height {epoch_start_height}) is {l1}"
    )]
    EpochStartTimestamp {
        epoch_start_height: u64,
        anchor: u32,
        l1: u32,
    },

    /// The anchor's next-block target differs from the target the anchor's
    /// successor is required to satisfy.
    #[error("next target: anchor declares {anchor}, L1 requires {l1}")]
    NextTarget { anchor: u32, l1: u32 },
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("ASM error: {0}")]
    AsmError(#[from] strata_asm_common::AsmError),

    #[error("missing genesis ASM state.")]
    MissingGenesisState,

    /// The anchor configured in `params` does not match the actual L1 chain.
    /// Surfaced at startup so a misconfigured anchor fails fast instead of one
    /// L1 block later, when header verification rejects the anchor's successor.
    #[error("configured anchor is inconsistent with the L1 chain: {0}")]
    AnchorMismatch(#[from] AnchorMismatch),

    #[error("missing l1 block {0:?}")]
    MissingL1Block(L1BlockId),

    #[error("missing ASM state for the block {0:?}")]
    MissingAsmState(L1BlockId),

    #[error("missing aux data for the block {0:?}")]
    MissingAuxData(L1BlockCommitment),

    /// A Bitcoin RPC call failed after exhausting its retry budget.
    ///
    /// Carries the underlying error as a `#[source]` so `Error::source()` chains
    /// all the way down to the concrete RPC error (e.g. `ClientError`), which
    /// stays recoverable via `downcast_ref`. The worker is generic over its
    /// `WorkerContext`, so it deliberately does not name the concrete RPC client
    /// type here; the context impl attaches call context (which call, which
    /// block) before wrapping.
    #[error("btc rpc: {0}")]
    BtcRpc(#[source] anyhow::Error),

    /// A backing store operation failed. Carries the underlying storage error as
    /// a `#[source]` so its full chain is preserved rather than bucketed into an
    /// opaque marker.
    #[error("db error: {0}")]
    DbError(#[source] anyhow::Error),

    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),

    #[error("not yet implemented")]
    Unimplemented,

    // Auxiliary data resolution errors
    #[error("Bitcoin transaction not found: {0:?}")]
    BitcoinTxNotFound(BitcoinTxid),

    #[error("L1 block not found at height {height}")]
    L1BlockNotFound { height: u64 },

    #[error("No ASM state available")]
    NoAsmState,

    #[error("Invalid manifest hash range: start={start}, end={end}")]
    InvalidManifestRange { start: u64, end: u64 },

    #[error("Invalid L1 height range: start={start}, end={end}")]
    InvalidHeightRange { start: u64, end: u64 },

    #[error("Manifest hash not found for MMR index {index}")]
    ManifestHashNotFound { index: u64 },

    #[error("MMR proof generation failed for index {index}")]
    MmrProofFailed { index: u64 },

    #[error("Manifest hash out of bound (max {max}, requested {index})")]
    ManifestIndexOutOfBound { index: u64, max: u64 },

    #[error("ASM worker exited unexpectedly")]
    WorkerExited,

    /// A service-framework operation failed for a reason other than the worker
    /// having exited (a cancelled wait, a panicked blocking thread, an unknown
    /// input). Carries the concrete [`ServiceError`] as a `#[source]` so the
    /// exact framework cause is preserved rather than flattened to a string.
    #[error("service framework error: {0}")]
    Service(#[source] ServiceError),

    /// Launching the worker through the service framework failed. The framework
    /// reports these as open-ended `anyhow` errors (thread spawn, runtime
    /// wiring), so carry the cause verbatim rather than bucketing it.
    #[error("failed to launch worker service: {0}")]
    ServiceLaunch(#[source] anyhow::Error),
}
