//! Storage trait for ASM anchor states.
//!
//! Each entry records the [`AnchorState`] computed after processing the L1 block
//! identified by the given [`L1BlockCommitment`]. Only the anchor state is
//! persistent state; the STF logs live in the manifest store.

use std::fmt::Debug;

use strata_asm_common::AnchorState;
use strata_identifiers::L1BlockCommitment;

/// Persistence interface for ASM anchor-state storage.
///
/// Async methods with an associated error type.
pub trait AsmStateDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores the anchor state, keyed by its own block commitment, without
    /// selecting it as the worker's active tip.
    ///
    /// This is the generic snapshot/backfill operation. Runtime worker commits
    /// use their concrete store's active-commit operation.
    fn put(&self, state: AnchorState) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the anchor state for the given L1 block commitment, if any.
    fn get(
        &self,
        block: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<AnchorState>, Self::Error>> + Send;

    /// Returns the commitment and anchor state at the worker's durable active
    /// tip.
    ///
    /// Block-keyed states from abandoned branches may be retained for replay and
    /// inspection, including states higher than the active tip after a shorter
    /// reorg. Implementations therefore track the active commitment explicitly;
    /// key ordering is not a safe proxy for chain selection.
    ///
    /// Returning the persisted commitment separately lets callers verify that
    /// the decoded state's embedded `last_processed_block` still matches the
    /// key selected by the active-tip record. Deriving both from the decoded
    /// value would make that corruption check tautological.
    fn get_latest(
        &self,
    ) -> impl Future<Output = Result<Option<(L1BlockCommitment, AnchorState)>, Self::Error>> + Send;

    /// Prunes all anchor states for blocks with height strictly below
    /// `before_height` — routine storage cleanup of old state.
    fn prune_before(
        &self,
        before_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Removes all anchor states for blocks with height strictly above
    /// `after_height` (which is kept).
    ///
    /// For manual intervention — e.g. rolling state back to a known-good height
    /// so the worker reprocesses from there.
    fn prune_after(
        &self,
        after_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
