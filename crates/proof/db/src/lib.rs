//! Sled-based proof storage.

use std::fmt::Debug;

use strata_asm_proof_types::{AsmProof, L1Range, MohoProof, ProofId, RemoteProofId};
use strata_identifiers::L1BlockCommitment;
use zkaleido::RemoteProofStatus;

mod sled;

pub use self::sled::{RemoteProofMappingError, RemoteProofStatusError, SledProofDb};

/// Persistence interface for proof storage.
pub trait ProofDb {
    /// The error type returned by the database operations.
    type Error: Debug;

    /// Stores an ASM step proof for the given L1 range.
    fn store_asm_proof(
        &self,
        range: L1Range,
        proof: AsmProof,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves an ASM step proof for the given L1 range, if one exists.
    fn get_asm_proof(
        &self,
        range: L1Range,
    ) -> impl Future<Output = Result<Option<AsmProof>, Self::Error>> + Send;

    /// Stores a Moho recursive proof anchored at the given L1 block commitment.
    fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves a Moho proof for the given L1 block commitment, if one exists.
    fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<MohoProof>, Self::Error>> + Send;

    /// Retrieves the latest (highest height) Moho proof and its L1 block commitment.
    ///
    /// Returns `None` if no Moho proofs have been stored yet.
    ///
    /// NOTE: Multiple proofs can exist at the same height (e.g. due to reorgs).
    /// In that case, the returned entry is determined by the underlying key
    /// ordering (height, then blkid bytes), which may be arbitrary. Callers that
    /// need the proof for a specific canonical block should use
    /// [`get_moho_proof`](Self::get_moho_proof) with the exact commitment.
    fn get_latest_moho_proof(
        &self,
    ) -> impl Future<Output = Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error>> + Send;

    /// Prunes all proofs (both ASM and Moho) for blocks before the given height.
    ///
    /// Deletes all entries with height strictly less than `before_height`.
    fn prune(&self, before_height: u32) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

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

/// Persistent store for the execution status of remote proof jobs.
///
/// Tracks only proofs whose results have **not yet been retrieved and stored
/// locally**. Once a proof is stored via [`ProofDb`], the corresponding status
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
