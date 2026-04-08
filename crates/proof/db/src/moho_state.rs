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
}
