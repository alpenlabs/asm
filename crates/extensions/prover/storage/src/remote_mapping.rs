//! Bidirectional mapping between local proof identifiers and remote prover
//! identifiers.

use std::fmt::Debug;

use strata_asm_prover_types::{ProofId, RemoteProofId};

/// Persistent bidirectional mapping between local [`ProofId`]s and
/// [`RemoteProofId`]s assigned by the remote prover service.
///
/// Used to prevent duplicate proof submissions and to recover the association
/// between local and remote identifiers after restarts.
pub trait RemoteProofMappingDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Returns the remote proof ID associated with the given local proof ID, if one exists.
    fn get_remote_proof_id(
        &self,
        id: ProofId,
    ) -> impl Future<Output = Result<Option<RemoteProofId>, Self::Error>> + Send;

    /// Returns the local proof ID associated with the given remote proof ID, if one exists.
    fn get_proof_id(
        &self,
        remote_id: &RemoteProofId,
    ) -> impl Future<Output = Result<Option<ProofId>, Self::Error>> + Send;

    /// Atomically stores both mapping directions and an initial Requested status.
    ///
    /// A proof may have multiple remote jobs. The newest one wins the forward
    /// lookup, while earlier jobs still resolve to their original proof.
    /// Reusing a remote ID for a different proof returns an error.
    /// Repeating a mapping restores its forward entry and any missing status;
    /// an existing status is preserved.
    fn put_remote_proof_id(
        &self,
        id: ProofId,
        remote_id: RemoteProofId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Forgets that `id` was submitted to the remote prover, so it can be
    /// submitted again. Returns whether a submission was on record.
    ///
    /// Only the proof → remote direction is cleared. The remote ids the proof
    /// has already had stay resolvable, so a late reply from one of them still
    /// names the proof it belongs to.
    fn clear_remote_proof_id(
        &self,
        id: ProofId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}
