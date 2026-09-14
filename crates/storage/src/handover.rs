//! Storage trait for the ASM predicate handover chain.
//!
//! Each entry records the predicate that authorizes the block *after* the one
//! identified by the key. That value decides which consensus rules the next
//! block executes under, so the chain is as load-bearing as the anchor states
//! themselves.

use std::fmt::Debug;

use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;

/// Persistence interface for the predicate handover chain.
///
/// Async methods with an associated error type. Entries are keyed by the block
/// that *hands over*, not the block that consumes the handover, so writing one
/// needs only the block just executed.
pub trait AsmHandoverDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores the predicate authorizing the block after `block`.
    ///
    /// Idempotent: the value is derived deterministically from the block, so
    /// replaying an uncommitted block rewrites the same entry.
    fn put(
        &self,
        block: L1BlockCommitment,
        predicate: PredicateKey,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the predicate authorizing the block after `block`, if stored.
    fn get(
        &self,
        block: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<PredicateKey>, Self::Error>> + Send;

    /// Removes handovers for blocks with height strictly above `after_height`,
    /// which is kept, as an explicit maintenance operation.
    ///
    /// Runtime reorg handling must not call this while the corresponding anchor
    /// states are retained. Entries are keyed by full block commitment, so
    /// another branch cannot select them; removing them alone would instead
    /// leave committed orphan anchors unrecoverable after a crash or later
    /// switch back.
    fn prune_after(
        &self,
        after_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
