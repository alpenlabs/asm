use strata_identifiers::L1BlockCommitment;
use thiserror::Error;

/// Return type for Moho worker operations.
pub type MohoWorkerResult<T> = Result<T, MohoWorkerError>;

#[derive(Debug, Error)]
pub enum MohoWorkerError {
    /// The ASM anchor state the Moho state derives from was not found. The ASM
    /// worker commits the anchor state before emitting its block notification,
    /// so a miss here means the ASM and Moho stores are out of sync.
    #[error("missing ASM anchor state for block {0:?}")]
    MissingAsmState(L1BlockCommitment),

    /// An incoming ASM commit skipped one or more heights relative to the
    /// worker's running state. The worker is a forward-only fold over the commit
    /// stream, so it cannot chain across a gap.
    // TODO(STR-3124): backfill the gap by replaying the intervening anchor
    // states instead of erroring out, once the worker resumes from its own
    // store on restart.
    #[error("non-contiguous ASM commit: expected height {expected}, got {got}")]
    NonContiguousBlock { expected: u64, got: u64 },

    /// The underlying Moho-state store failed. Carries the backend's display so
    /// the operator sees the real cause without us bucketing it.
    #[error("moho state store: {0}")]
    Storage(String),

    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),
}
