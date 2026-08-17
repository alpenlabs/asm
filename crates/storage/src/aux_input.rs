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
    /// For manual intervention. Aux data is derived from the STF, not the
    /// worker's commit point, so this on its own does not make the worker
    /// reprocess anything — planning treats a block as processed once its
    /// anchor state exists. Dropping aux rows while their anchor states remain
    /// leaves the prover unable to build inputs for those blocks. To roll back,
    /// prune [`AsmStateDb`](crate::AsmStateDb) to the same height; reprocessing
    /// rewrites the aux data.
    fn prune_after(
        &self,
        after_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
