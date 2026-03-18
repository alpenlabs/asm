//! Bidirectional mapping between local proof identifiers and remote prover
//! identifiers.
//!
//! This mapping is used to prevent duplicate proof submissions and to recover
//! the association between local and remote identifiers after restarts.

use std::fmt::Debug;

use strata_asm_proof_types::{ProofId, RemoteProofId};

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

    /// Stores a mapping between a local proof ID and a remote proof ID.
    ///
    /// A single [`ProofId`] may be associated with multiple [`RemoteProofId`]s
    /// (e.g. when a proof is resubmitted), so calling this with the same
    /// `id` but a different `remote_id` is allowed — only the forward lookup
    /// (`ProofId → RemoteProofId`) is updated to point to the latest remote ID.
    ///
    /// However, a [`RemoteProofId`] must map to exactly one [`ProofId`].
    /// If `remote_id` is already associated with a **different** proof ID,
    /// this method returns an error.
    fn put_remote_proof_id(
        &self,
        id: ProofId,
        remote_id: RemoteProofId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
