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

    /// The Moho state for a block was not found in the store. Hit when
    /// resolving the parent of an incoming commit: the fold chains forward from
    /// the parent's committed Moho state, so the parent must already be present.
    /// With commits arriving in order from the ASM worker, a miss means the
    /// parent's commit was never folded — a gap the worker cannot bridge alone.
    // TODO(STR-3124): backfill the gap by replaying the intervening anchor
    // states instead of erroring out, once the worker resumes from its own
    // store on restart.
    #[error("missing Moho state for block {0:?}")]
    MissingMohoState(L1BlockCommitment),

    /// The parent of an L1 block commitment could not be resolved — e.g. the L1
    /// block or its header was unavailable from the provider.
    #[error("could not resolve parent of L1 block {0:?}")]
    MissingParentBlock(L1BlockCommitment),

    /// The underlying Moho-state store failed. Carries the backend's display so
    /// the operator sees the real cause without us bucketing it.
    #[error("moho state store: {0}")]
    Storage(String),

    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),
}
