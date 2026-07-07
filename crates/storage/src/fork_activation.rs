//! Storage trait for discovered fork activations.
//!
//! Each record says "the block at `enacting_height` enacted an ASM VK upgrade
//! that activates `fork` at `activation_height`" (the block after the enacting
//! one), carrying the predicate the upgrade switched the ASM STF to. The
//! worker persists a record *before* committing the enacting block's
//! anchor state, so an activation can never lag a committed anchor, and prunes
//! records above the fork point when a reorg abandons the enacting block.

use std::fmt::Debug;

use strata_asm_common::ForkActivation;

/// Persistence interface for fork-activation records.
///
/// Async methods with an associated error type.
pub trait AsmForkActivationDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores a fork activation, keyed by `(enacting_height, fork)`.
    ///
    /// Idempotent: replaying the enacting block rewrites the same record.
    fn put(
        &self,
        activation: ForkActivation,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns every stored activation, ascending by enacting height.
    fn list(&self) -> impl Future<Output = Result<Vec<ForkActivation>, Self::Error>> + Send;

    /// Removes all activations whose enacting height is strictly above
    /// `after_height` (which is kept). Used on reorgs to drop activations
    /// enacted on the abandoned branch.
    fn prune_after(
        &self,
        after_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
