//! Durable record of each remote proof submission.
//!
//! One record ties a logical proof task to the remote prover's id, the last
//! observed status, and the exact program and artifact identity that produced
//! it. Keeping provenance in the same record as the mapping is what lets a
//! completed proof be decoded through the host that made it, and stops a retry
//! reinterpreting an in-flight attempt under a different artifact.
//!
//! Implementations must store the record and its active index in one atomic
//! write, so a mapping can never become visible without its status and
//! provenance.
//!
//! TODO(ASM-UP-017): a submission is accepted remotely before the local record
//! is written, so a crash in between can leave an attempt that exists remotely
//! and not locally. Closing that needs a prepared / acceptance-unknown /
//! accepted lifecycle in place of the `status` plus `remote_id` pair, which is
//! a crash-recovery change independent of artifact identity. It is deferred to
//! the prover reliability work rather than mixed into this one.

use std::fmt::Debug;

use strata_asm_prover_types::{ProofId, ProofJobIdentity, RemoteProofId, RemoteProofJob};
use zkaleido::RemoteProofStatus;

/// Persistence interface for remote proof job records.
pub trait RemoteProofJobDb {
    /// Error type surfaced by the backing store.
    type Error: Debug;

    /// Returns the active job for `proof_id`, if one is in flight.
    fn get_active_remote_proof_job(
        &self,
        proof_id: ProofId,
    ) -> impl Future<Output = Result<Option<RemoteProofJob>, Self::Error>> + Send;

    /// Returns the job a remote id belongs to, active or terminal.
    fn get_remote_proof_job(
        &self,
        remote_id: &RemoteProofId,
    ) -> impl Future<Output = Result<Option<RemoteProofJob>, Self::Error>> + Send;

    /// Records a newly submitted job and claims the active slot for its task.
    ///
    /// Refused when the task already has an active job, so a duplicate
    /// submission cannot leave two records competing for one slot.
    fn create_remote_proof_job(
        &self,
        job: RemoteProofJob,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Attaches an identity to a job recorded before provenance was tracked.
    ///
    /// Applies once: an attempt that already carries an identity keeps it,
    /// since re-binding would let a restart reinterpret which artifact proved a
    /// block.
    fn bind_legacy_remote_proof_job(
        &self,
        remote_id: &RemoteProofId,
        identity: ProofJobIdentity,
    ) -> impl Future<Output = Result<RemoteProofJob, Self::Error>> + Send;

    /// Advances a job's status, compare-and-set against `expected`.
    ///
    /// The guard is what makes a late update from a superseded reconciliation
    /// pass fail instead of overwriting a newer status.
    fn update_remote_proof_job_status(
        &self,
        remote_id: &RemoteProofId,
        expected: RemoteProofStatus,
        status: RemoteProofStatus,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Moves a job to a terminal status and releases its active slot.
    ///
    /// Releasing the slot in the same write is what lets a failed proof be
    /// re-enqueued in the same cycle rather than waiting for a restart.
    fn finish_remote_proof_job(
        &self,
        remote_id: &RemoteProofId,
        expected: RemoteProofStatus,
        status: RemoteProofStatus,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns every job still holding an active slot, for reconciliation.
    fn get_all_active_remote_proof_jobs(
        &self,
    ) -> impl Future<Output = Result<Vec<RemoteProofJob>, Self::Error>> + Send;
}
