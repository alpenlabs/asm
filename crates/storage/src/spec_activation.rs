//! Storage trait for discovered spec activations.
//!
//! Each row says "the block at `enacting_height` enacted an ASM VK upgrade
//! that activates spec version `version`", carrying the predicate the upgrade
//! switched the ASM STF to. The version travels as its raw u16 id: mapping it
//! to a known spec version is act-time worker logic, so the store passes it
//! through opaquely (the worker's `SpecActivationRecord` is the typed form).
//! The worker persists a row *before* committing the enacting block's anchor
//! state, so an activation can never lag a committed anchor, and prunes rows
//! above the fork point when a reorg abandons the enacting block.

use std::fmt::Debug;

use strata_identifiers::L1Height;
use strata_predicate::PredicateKey;

/// A stored spec activation row: the enacting height, the raw spec version
/// id, and the predicate the upgrade enacted.
pub type RawSpecActivation = (L1Height, u16, PredicateKey);

/// Persistence interface for spec-activation rows.
///
/// Async methods with an associated error type.
pub trait AsmSpecActivationDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores a spec activation, keyed by `(enacting_height, version)`.
    ///
    /// Idempotent: replaying the enacting block rewrites the same row.
    fn put(
        &self,
        enacting_height: L1Height,
        version: u16,
        new_predicate: &PredicateKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns every stored activation, ascending by enacting height.
    fn list(&self) -> impl Future<Output = Result<Vec<RawSpecActivation>, Self::Error>> + Send;

    /// Removes all activations whose enacting height is strictly above
    /// `after_height` (which is kept). Used on reorgs to drop activations
    /// enacted on the abandoned branch.
    fn prune_after(
        &self,
        after_height: L1Height,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
