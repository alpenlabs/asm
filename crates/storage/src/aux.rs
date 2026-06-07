//! Storage trait for ASM auxiliary data.
//!
//! Each entry records the [`AuxData`] resolved for the L1 block identified by
//! the given [`L1BlockCommitment`], for later prover consumption.

use std::fmt::Debug;

use strata_asm_common::AuxData;
use strata_identifiers::L1BlockCommitment;

/// Persistence interface for ASM auxiliary-data storage.
///
/// Async methods with an associated error type. Unlike the state stores there is
/// no `get_latest`: aux data is only ever looked up for a specific block.
pub trait AsmAuxDataDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores the auxiliary data for the given L1 block commitment.
    fn put(
        &self,
        block: L1BlockCommitment,
        data: AuxData,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the auxiliary data for the given L1 block commitment, if any.
    fn get(
        &self,
        block: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<AuxData>, Self::Error>> + Send;

    /// Prunes all auxiliary data for blocks with height strictly below
    /// `before_height` — routine storage cleanup of old data.
    fn prune_before(
        &self,
        before_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Removes all auxiliary data for blocks with height strictly above
    /// `after_height` (which is kept).
    ///
    /// For manual intervention — e.g. rolling storage back to a known-good
    /// height so the worker reprocesses from there.
    fn prune_after(
        &self,
        after_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
