//! Storage trait for ASM anchor states.
//!
//! Each entry records the [`AnchorState`] computed after processing the L1 block
//! identified by the given [`L1BlockCommitment`]. The worker's `AsmState`
//! umbrella (anchor state plus logs) is deliberately not stored here: only the
//! anchor state is persistent state; the logs live in the manifest store.

use std::fmt::Debug;

use strata_asm_common::AnchorState;
use strata_identifiers::L1BlockCommitment;

/// Persistence interface for ASM anchor-state storage.
///
/// Async methods with an associated error type.
pub trait AsmStateDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores the anchor state, keyed by its own block commitment
    /// (`chain_view.pow_state.last_verified_block`).
    fn put(&self, state: AnchorState) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the anchor state for the given L1 block commitment, if any.
    fn get(
        &self,
        block: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<AnchorState>, Self::Error>> + Send;

    /// Returns the highest-height stored anchor state.
    ///
    /// NOTE: multiple anchor states can exist at the same height (e.g. due to
    /// reorgs). In that case the entry returned is determined by the underlying
    /// key ordering (height, then block-id bytes), which may be arbitrary.
    /// Callers that need a specific canonical block should use [`get`](Self::get)
    /// with the exact commitment.
    fn get_latest(&self) -> impl Future<Output = Result<Option<AnchorState>, Self::Error>> + Send;

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
