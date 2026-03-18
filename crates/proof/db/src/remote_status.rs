//! Status tracking for in-flight remote proof jobs.
//!
//! Entries are created when a proof is submitted to the remote prover and
//! removed once the result has been retrieved and stored locally via
//! [`ProofDb`](crate::ProofDb).

use std::fmt::Debug;

use strata_asm_proof_types::RemoteProofId;
use zkaleido::RemoteProofStatus;

/// Persistent store for the execution status of remote proof jobs.
///
/// Tracks only proofs whose results have **not yet been retrieved and stored
/// locally**. Once a proof is stored via [`ProofDb`](crate::ProofDb), the corresponding status
/// entry should be removed.
pub trait RemoteProofStatusDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Inserts a new status entry for the given remote proof ID.
    ///
    /// Returns an error if an entry already exists for this ID.
    fn put_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Updates the status of an existing remote proof entry.
    ///
    /// Returns an error if no entry exists for this ID.
    fn update_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns the current status of the given remote proof, if tracked.
    fn get_status(
        &self,
        remote_id: &RemoteProofId,
    ) -> impl Future<Output = Result<Option<RemoteProofStatus>, Self::Error>> + Send;

    /// Returns all remote proofs that are currently active (i.e. `Requested` or `InProgress`).
    fn get_all_in_progress(
        &self,
    ) -> impl Future<Output = Result<Vec<(RemoteProofId, RemoteProofStatus)>, Self::Error>> + Send;

    /// Removes the status entry for the given remote proof ID.
    fn remove(
        &self,
        remote_id: &RemoteProofId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
