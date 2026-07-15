//! Storage trait for Moho state snapshots.
//!
//! Each entry records the [`MohoState`] that was computed after processing the
//! L1 block identified by the given [`L1BlockCommitment`].

use std::fmt::Debug;

use moho_types::MohoState;
use strata_identifiers::L1BlockCommitment;

/// Persistence interface for Moho state storage.
pub trait MohoStateDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores the Moho state anchored at the given L1 block commitment.
    fn store_moho_state(
        &self,
        l1ref: L1BlockCommitment,
        state: MohoState,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the Moho state for the given L1 block commitment, if one exists.
    fn get_moho_state(
        &self,
        l1ref: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<MohoState>, Self::Error>> + Send;

    /// Retrieves the highest-height stored Moho state and the block it is
    /// anchored to, or `None` when the store is empty.
    fn get_latest_moho_state(
        &self,
    ) -> impl Future<Output = Result<Option<(L1BlockCommitment, MohoState)>, Self::Error>> + Send;

    /// Prunes all Moho state entries for blocks before the given height.
    ///
    /// Deletes all entries with height strictly less than `before_height`.
    fn prune(&self, before_height: u32) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
