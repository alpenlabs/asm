//! Atomic [`RemoteProofJobDb`](crate::RemoteProofJobDb) implementation.

use std::{error::Error, fmt};

use borsh::BorshDeserialize;
use sled::transaction::{ConflictableTransactionError, TransactionError};
use strata_asm_prover_types::{ProofId, ProofJobIdentity, RemoteProofId, RemoteProofJob};
use zkaleido::RemoteProofStatus;

use super::SledProofDb;
use crate::RemoteProofJobDb;

const JOB_PREFIX: u8 = 0;
const ACTIVE_PREFIX: u8 = 1;
const MIGRATION_KEY: &[u8] = &[2, 1];

/// Errors returned by the sled-backed remote-job store.
#[derive(Debug)]
pub enum RemoteProofJobError {
    /// The underlying sled database returned an error.
    Db(sled::Error),
    /// A stored job record failed to decode.
    CorruptRecord(String),
    /// Another active attempt already owns this logical proof task.
    AlreadyActive {
        /// Logical proof task.
        proof_id: ProofId,
        /// Existing active remote attempt.
        remote_id: RemoteProofId,
    },
    /// The remote id is already used by another job.
    DuplicateRemoteId(RemoteProofId),
    /// The requested remote job does not exist.
    NotFound(RemoteProofId),
    /// An operation expected the job to be active, but it was historical.
    NotActive(RemoteProofId),
    /// The caller raced a status transition and supplied a stale expectation.
    StatusConflict {
        /// Remote job being updated.
        remote_id: RemoteProofId,
        /// Status supplied by the caller.
        expected: RemoteProofStatus,
        /// Status currently stored.
        actual: RemoteProofStatus,
    },
    /// A qualified job identity was changed or did not match the proof kind.
    IdentityConflict(RemoteProofId),
    /// A new job violated a lifecycle invariant.
    InvalidJob(&'static str),
}

impl fmt::Display for RemoteProofJobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(error) => write!(f, "sled error: {error}"),
            Self::CorruptRecord(error) => write!(f, "corrupt remote proof job: {error}"),
            Self::AlreadyActive {
                proof_id,
                remote_id,
            } => write!(
                f,
                "proof {proof_id} already has active remote job {remote_id}"
            ),
            Self::DuplicateRemoteId(remote_id) => {
                write!(f, "remote proof id {remote_id} is already in use")
            }
            Self::NotFound(remote_id) => write!(f, "remote proof job {remote_id} not found"),
            Self::NotActive(remote_id) => write!(f, "remote proof job {remote_id} is not active"),
            Self::StatusConflict {
                remote_id,
                expected,
                actual,
            } => write!(
                f,
                "remote proof job {remote_id} status changed: expected {expected:?}, found {actual:?}"
            ),
            Self::IdentityConflict(remote_id) => {
                write!(f, "remote proof job {remote_id} has a conflicting identity")
            }
            Self::InvalidJob(reason) => write!(f, "invalid remote proof job: {reason}"),
        }
    }
}

impl Error for RemoteProofJobError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Db(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sled::Error> for RemoteProofJobError {
    fn from(error: sled::Error) -> Self {
        Self::Db(error)
    }
}

fn job_key(remote_id: &RemoteProofId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + remote_id.0.len());
    key.push(JOB_PREFIX);
    key.extend_from_slice(&remote_id.0);
    key
}

fn active_key(proof_id: ProofId) -> Vec<u8> {
    let encoded = borsh::to_vec(&proof_id).expect("ProofId borsh serialization cannot fail");
    let mut key = Vec::with_capacity(1 + encoded.len());
    key.push(ACTIVE_PREFIX);
    key.extend_from_slice(&encoded);
    key
}

fn decode_job(bytes: &[u8]) -> Result<RemoteProofJob, RemoteProofJobError> {
    RemoteProofJob::try_from_slice(bytes)
        .map_err(|error| RemoteProofJobError::CorruptRecord(error.to_string()))
}

fn decode_legacy<T: BorshDeserialize>(bytes: &[u8], what: &str) -> Result<T, sled::Error> {
    T::try_from_slice(bytes)
        .map_err(|error| sled::Error::Unsupported(format!("corrupt legacy {what} row: {error}")))
}

fn abort<T>(
    error: RemoteProofJobError,
) -> Result<T, ConflictableTransactionError<RemoteProofJobError>> {
    Err(ConflictableTransactionError::Abort(error))
}

fn map_transaction_error(error: TransactionError<RemoteProofJobError>) -> RemoteProofJobError {
    match error {
        TransactionError::Abort(error) => error,
        TransactionError::Storage(error) => RemoteProofJobError::Db(error),
    }
}

fn is_terminal(status: &RemoteProofStatus) -> bool {
    matches!(
        status,
        RemoteProofStatus::Completed | RemoteProofStatus::Failed(_)
    )
}

fn validate_identity(proof_id: ProofId, identity: &ProofJobIdentity) -> bool {
    matches!(
        (proof_id, identity),
        (ProofId::Asm(_), ProofJobIdentity::Asm(_))
            | (ProofId::Asm(_), ProofJobIdentity::LegacyUnqualifiedAsm)
            | (ProofId::Moho(_), ProofJobIdentity::Moho(_))
            | (ProofId::Moho(_), ProofJobIdentity::LegacyUnqualifiedMoho)
    )
}

impl SledProofDb {
    /// Returns one authoritative job by remote id.
    pub fn remote_job(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<RemoteProofJob>, RemoteProofJobError> {
        self.remote_proof_jobs
            .get(job_key(remote_id))?
            .map(|bytes| decode_job(&bytes))
            .transpose()
    }

    /// Returns the authoritative active job for a logical proof task.
    pub fn active_remote_job(
        &self,
        proof_id: ProofId,
    ) -> Result<Option<RemoteProofJob>, RemoteProofJobError> {
        let Some(remote_bytes) = self.remote_proof_jobs.get(active_key(proof_id))? else {
            return Ok(None);
        };
        let remote_id = RemoteProofId(remote_bytes.to_vec());
        let job = self.remote_job(&remote_id)?.ok_or_else(|| {
            RemoteProofJobError::CorruptRecord(format!(
                "active index for {proof_id} points to missing job {remote_id}"
            ))
        })?;
        if job.proof_id != proof_id || job.remote_id != remote_id {
            return Err(RemoteProofJobError::CorruptRecord(format!(
                "active index for {proof_id} points to inconsistent job {remote_id}"
            )));
        }
        Ok(Some(job))
    }

    /// Lists every authoritative job, including terminal audit history.
    pub fn list_remote_jobs(&self) -> Result<Vec<RemoteProofJob>, RemoteProofJobError> {
        self.remote_proof_jobs
            .scan_prefix([JOB_PREFIX])
            .map(|entry| {
                let (_, value) = entry?;
                decode_job(&value)
            })
            .collect()
    }

    fn has_stored_proof(&self, proof_id: ProofId) -> Result<bool, sled::Error> {
        match proof_id {
            ProofId::Asm(range) => self.asm_proofs.contains_key(super::encode_asm_key(&range)),
            ProofId::Moho(block) => self
                .moho_proofs
                .contains_key(super::encode_moho_key(&block)),
        }
    }

    fn insert_migrated_job(
        &self,
        job: RemoteProofJob,
        active: bool,
    ) -> Result<(), RemoteProofJobError> {
        let job_key = job_key(&job.remote_id);
        let active_key = active_key(job.proof_id);
        let encoded = borsh::to_vec(&job).expect("RemoteProofJob borsh serialization cannot fail");
        let remote_bytes = job.remote_id.0.clone();

        self.remote_proof_jobs
            .transaction(|tree| {
                let existing_job = tree.get(&job_key)?;
                let existing_active = tree.get(&active_key)?;
                match (existing_job, existing_active, active) {
                    (None, None, _) => {}
                    (Some(bytes), Some(remote), true) => {
                        let existing =
                            decode_job(&bytes).map_err(ConflictableTransactionError::Abort)?;
                        if existing == job && remote.as_ref() == remote_bytes.as_slice() {
                            return Ok(());
                        }
                        return abort(RemoteProofJobError::CorruptRecord(format!(
                            "legacy job {} conflicts with an existing job or active index",
                            job.remote_id
                        )));
                    }
                    (Some(bytes), None, false) => {
                        let existing =
                            decode_job(&bytes).map_err(ConflictableTransactionError::Abort)?;
                        if existing == job {
                            return Ok(());
                        }
                        return abort(RemoteProofJobError::CorruptRecord(format!(
                            "legacy job {} conflicts with an existing historical job",
                            job.remote_id
                        )));
                    }
                    _ => {
                        return abort(RemoteProofJobError::CorruptRecord(format!(
                            "legacy job {} found a partial job/index pair",
                            job.remote_id
                        )));
                    }
                }
                tree.insert(job_key.as_slice(), encoded.as_slice())?;
                if active {
                    tree.insert(active_key.as_slice(), remote_bytes.as_slice())?;
                }
                Ok(())
            })
            .map_err(map_transaction_error)
    }

    /// Imports rows from the split legacy mapping/status trees once.
    ///
    /// A forward mapping without a status is the exact historical crash window
    /// this store replaces. If no local proof exists, it is recovered as
    /// `Requested`, so restart polling can discover the remote service's real
    /// state. The old worker also retained mappings after successful jobs; a
    /// matching local proof therefore imports that row as inactive `Completed`
    /// history instead of consuming capacity or polling an expired remote id.
    /// Legacy ASM rows remain explicitly unqualified until the worker binds an
    /// active one through authenticated state and a qualified local artifact.
    pub(super) fn migrate_legacy_remote_jobs(&self) -> Result<(), sled::Error> {
        if self.remote_proof_jobs.get(MIGRATION_KEY)?.is_some() {
            return Ok(());
        }

        // Forward mappings are authoritative for deduplication. Migrate these
        // first, including mapping-only rows left by the old two-write path.
        for entry in &self.proof_to_remote {
            let (proof_bytes, remote_bytes) = entry?;
            let proof_id = decode_legacy(&proof_bytes, "forward ProofId")?;
            let remote_id = RemoteProofId(remote_bytes.to_vec());
            if let Some(reverse_bytes) = self.remote_to_proof.get(&remote_id.0)? {
                let reverse_proof_id: ProofId = decode_legacy(&reverse_bytes, "reverse ProofId")?;
                if reverse_proof_id != proof_id {
                    return Err(sled::Error::Unsupported(format!(
                        "legacy forward mapping for {proof_id} conflicts with reverse mapping for {reverse_proof_id}"
                    )));
                }
            }
            let locally_completed = self.has_stored_proof(proof_id)?;
            let status = if locally_completed {
                RemoteProofStatus::Completed
            } else {
                self.remote_proof_status
                    .get(&remote_id.0)?
                    .map(|bytes| decode_legacy(&bytes, "status"))
                    .transpose()?
                    .unwrap_or(RemoteProofStatus::Requested)
            };
            let identity = match proof_id {
                ProofId::Asm(_) => ProofJobIdentity::LegacyUnqualifiedAsm,
                ProofId::Moho(_) => ProofJobIdentity::LegacyUnqualifiedMoho,
            };
            self.insert_migrated_job(
                RemoteProofJob {
                    proof_id,
                    remote_id,
                    identity,
                    status,
                },
                !locally_completed,
            )
            .map_err(|error| sled::Error::Unsupported(error.to_string()))?;
        }

        // A crash during failed-job cleanup could remove the forward mapping
        // while leaving status tracking active. Preserve those jobs too.
        for entry in &self.remote_proof_status {
            let (remote_bytes, status_bytes) = entry?;
            let remote_id = RemoteProofId(remote_bytes.to_vec());
            let Some(proof_bytes) = self.remote_to_proof.get(&remote_id.0)? else {
                return Err(sled::Error::Unsupported(format!(
                    "legacy status for remote proof {remote_id} has no reverse mapping"
                )));
            };
            let proof_id = decode_legacy(&proof_bytes, "reverse ProofId")?;
            if let Some(existing) = self
                .remote_job(&remote_id)
                .map_err(|error| sled::Error::Unsupported(error.to_string()))?
            {
                if existing.proof_id != proof_id {
                    return Err(sled::Error::Unsupported(format!(
                        "legacy status for {remote_id} maps to {proof_id}, but its job maps to {}",
                        existing.proof_id
                    )));
                }
                let active = self
                    .active_remote_job(existing.proof_id)
                    .map_err(|error| sled::Error::Unsupported(error.to_string()))?;
                let is_active = active.as_ref().map(|job| &job.remote_id) == Some(&remote_id);
                let is_completed_history = active.is_none()
                    && existing.status == RemoteProofStatus::Completed
                    && self.has_stored_proof(proof_id)?;
                if !is_active && !is_completed_history {
                    return Err(sled::Error::Unsupported(format!(
                        "legacy status for {remote_id} conflicts with a non-active job record"
                    )));
                }
                continue;
            }
            let locally_completed = self.has_stored_proof(proof_id)?;
            let status = if locally_completed {
                RemoteProofStatus::Completed
            } else {
                decode_legacy(&status_bytes, "status")?
            };
            let identity = match proof_id {
                ProofId::Asm(_) => ProofJobIdentity::LegacyUnqualifiedAsm,
                ProofId::Moho(_) => ProofJobIdentity::LegacyUnqualifiedMoho,
            };
            self.insert_migrated_job(
                RemoteProofJob {
                    proof_id,
                    remote_id,
                    identity,
                    status,
                },
                !locally_completed,
            )
            .map_err(|error| sled::Error::Unsupported(error.to_string()))?;
        }

        self.remote_proof_jobs.insert(MIGRATION_KEY, &[])?;
        self.remote_proof_jobs.flush()?;
        Ok(())
    }

    /// Lists all active authoritative jobs synchronously for offline tooling.
    pub fn active_remote_jobs(&self) -> Result<Vec<RemoteProofJob>, RemoteProofJobError> {
        self.remote_proof_jobs
            .scan_prefix([ACTIVE_PREFIX])
            .map(|entry| {
                let (key, remote_bytes) = entry?;
                let proof_id = ProofId::try_from_slice(&key[1..])
                    .map_err(|error| RemoteProofJobError::CorruptRecord(error.to_string()))?;
                let remote_id = RemoteProofId(remote_bytes.to_vec());
                let job = self.remote_job(&remote_id)?.ok_or_else(|| {
                    RemoteProofJobError::CorruptRecord(format!(
                        "active index for {proof_id} points to missing job {remote_id}"
                    ))
                })?;
                if job.proof_id != proof_id {
                    return Err(RemoteProofJobError::CorruptRecord(format!(
                        "active index for {proof_id} points to job for {}",
                        job.proof_id
                    )));
                }
                Ok(job)
            })
            .collect()
    }
}

impl RemoteProofJobDb for SledProofDb {
    type Error = RemoteProofJobError;

    async fn get_active_remote_proof_job(
        &self,
        proof_id: ProofId,
    ) -> Result<Option<RemoteProofJob>, Self::Error> {
        self.active_remote_job(proof_id)
    }

    async fn get_remote_proof_job(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<RemoteProofJob>, Self::Error> {
        self.remote_job(remote_id)
    }

    async fn create_remote_proof_job(&self, job: RemoteProofJob) -> Result<(), Self::Error> {
        if job.status != RemoteProofStatus::Requested {
            return Err(RemoteProofJobError::InvalidJob(
                "new jobs must start in Requested status",
            ));
        }
        if matches!(
            job.identity,
            ProofJobIdentity::LegacyUnqualifiedAsm | ProofJobIdentity::LegacyUnqualifiedMoho
        ) {
            return Err(RemoteProofJobError::InvalidJob(
                "new jobs must carry a qualified artifact identity",
            ));
        }
        if !validate_identity(job.proof_id, &job.identity) {
            return Err(RemoteProofJobError::InvalidJob(
                "proof kind and program identity disagree",
            ));
        }

        let job_key = job_key(&job.remote_id);
        let active_key = active_key(job.proof_id);
        let encoded = borsh::to_vec(&job).expect("RemoteProofJob borsh serialization cannot fail");
        let remote_bytes = job.remote_id.0.clone();

        self.remote_proof_jobs
            .transaction(|tree| {
                if let Some(existing_bytes) = tree.get(&job_key)? {
                    let existing =
                        decode_job(&existing_bytes).map_err(ConflictableTransactionError::Abort)?;
                    if existing == job
                        && tree.get(&active_key)?.as_deref() == Some(remote_bytes.as_slice())
                    {
                        return Ok(());
                    }
                    return abort(RemoteProofJobError::DuplicateRemoteId(
                        job.remote_id.clone(),
                    ));
                }

                if let Some(existing_remote) = tree.get(&active_key)? {
                    return abort(RemoteProofJobError::AlreadyActive {
                        proof_id: job.proof_id,
                        remote_id: RemoteProofId(existing_remote.to_vec()),
                    });
                }

                tree.insert(job_key.as_slice(), encoded.as_slice())?;
                tree.insert(active_key.as_slice(), remote_bytes.as_slice())?;
                Ok(())
            })
            .map_err(map_transaction_error)?;
        self.remote_proof_jobs.flush_async().await?;
        Ok(())
    }

    async fn bind_legacy_remote_proof_job(
        &self,
        remote_id: &RemoteProofId,
        identity: ProofJobIdentity,
    ) -> Result<RemoteProofJob, Self::Error> {
        if matches!(
            identity,
            ProofJobIdentity::LegacyUnqualifiedAsm | ProofJobIdentity::LegacyUnqualifiedMoho
        ) {
            return Err(RemoteProofJobError::IdentityConflict(remote_id.clone()));
        }
        let key = job_key(remote_id);
        let job = self
            .remote_proof_jobs
            .transaction(|tree| {
                let Some(bytes) = tree.get(&key)? else {
                    return abort(RemoteProofJobError::NotFound(remote_id.clone()));
                };
                let mut job = decode_job(&bytes).map_err(ConflictableTransactionError::Abort)?;
                if tree.get(active_key(job.proof_id))?.as_deref() != Some(remote_id.0.as_slice()) {
                    return abort(RemoteProofJobError::NotActive(remote_id.clone()));
                }
                if job.identity == identity {
                    return Ok(job);
                }
                let is_matching_legacy = matches!(
                    (&job.identity, &identity),
                    (
                        ProofJobIdentity::LegacyUnqualifiedAsm,
                        ProofJobIdentity::Asm(_)
                    ) | (
                        ProofJobIdentity::LegacyUnqualifiedMoho,
                        ProofJobIdentity::Moho(_)
                    )
                );
                if !is_matching_legacy || !validate_identity(job.proof_id, &identity) {
                    return abort(RemoteProofJobError::IdentityConflict(remote_id.clone()));
                }
                job.identity = identity.clone();
                let encoded =
                    borsh::to_vec(&job).expect("RemoteProofJob borsh serialization cannot fail");
                tree.insert(key.as_slice(), encoded.as_slice())?;
                Ok(job)
            })
            .map_err(map_transaction_error)?;
        self.remote_proof_jobs.flush_async().await?;
        Ok(job)
    }

    async fn update_remote_proof_job_status(
        &self,
        remote_id: &RemoteProofId,
        expected: RemoteProofStatus,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        if is_terminal(&status) {
            return Err(RemoteProofJobError::InvalidJob(
                "terminal status must use finish_remote_proof_job",
            ));
        }
        let key = job_key(remote_id);
        self.remote_proof_jobs
            .transaction(|tree| {
                let Some(bytes) = tree.get(&key)? else {
                    return abort(RemoteProofJobError::NotFound(remote_id.clone()));
                };
                let mut job = decode_job(&bytes).map_err(ConflictableTransactionError::Abort)?;
                if tree.get(active_key(job.proof_id))?.as_deref() != Some(remote_id.0.as_slice()) {
                    return abort(RemoteProofJobError::NotActive(remote_id.clone()));
                }
                if job.status != expected {
                    return abort(RemoteProofJobError::StatusConflict {
                        remote_id: remote_id.clone(),
                        expected: expected.clone(),
                        actual: job.status,
                    });
                }
                job.status = status.clone();
                let encoded =
                    borsh::to_vec(&job).expect("RemoteProofJob borsh serialization cannot fail");
                tree.insert(key.as_slice(), encoded.as_slice())?;
                Ok(())
            })
            .map_err(map_transaction_error)?;
        self.remote_proof_jobs.flush_async().await?;
        Ok(())
    }

    async fn finish_remote_proof_job(
        &self,
        remote_id: &RemoteProofId,
        expected: RemoteProofStatus,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        if !is_terminal(&status) {
            return Err(RemoteProofJobError::InvalidJob(
                "finished jobs require Completed or Failed status",
            ));
        }
        let key = job_key(remote_id);
        self.remote_proof_jobs
            .transaction(|tree| {
                let Some(bytes) = tree.get(&key)? else {
                    return abort(RemoteProofJobError::NotFound(remote_id.clone()));
                };
                let mut job = decode_job(&bytes).map_err(ConflictableTransactionError::Abort)?;

                // Replaying the same terminal transition is harmless.
                if job.status == status
                    && tree.get(active_key(job.proof_id))?.as_deref()
                        != Some(remote_id.0.as_slice())
                {
                    return Ok(());
                }
                if job.status != expected {
                    return abort(RemoteProofJobError::StatusConflict {
                        remote_id: remote_id.clone(),
                        expected: expected.clone(),
                        actual: job.status,
                    });
                }

                let active_key = active_key(job.proof_id);
                if tree.get(&active_key)?.as_deref() == Some(remote_id.0.as_slice()) {
                    tree.remove(active_key.as_slice())?;
                }
                job.status = status.clone();
                let encoded =
                    borsh::to_vec(&job).expect("RemoteProofJob borsh serialization cannot fail");
                tree.insert(key.as_slice(), encoded.as_slice())?;
                Ok(())
            })
            .map_err(map_transaction_error)?;
        self.remote_proof_jobs.flush_async().await?;
        Ok(())
    }

    async fn get_all_active_remote_proof_jobs(&self) -> Result<Vec<RemoteProofJob>, Self::Error> {
        self.active_remote_jobs()
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{AsmArtifactId, AsmSpecId, GuestArtifactId};
    use strata_asm_prover_types::{
        AsmProofJobIdentity, L1Range, MohoProofJobIdentity, ProofJobIdentity,
    };
    use strata_identifiers::{L1BlockCommitment, L1BlockId};
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use zkaleido::RemoteProofFailureReason;

    use super::*;
    use crate::sled::encode_moho_key;

    fn block(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    fn moho_job(height: u32, remote: u8) -> RemoteProofJob {
        RemoteProofJob {
            proof_id: ProofId::Moho(block(height)),
            remote_id: RemoteProofId(vec![remote]),
            identity: ProofJobIdentity::Moho(MohoProofJobIdentity {
                predicate: PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![0x44; 32])
                    .unwrap(),
                artifact_id: GuestArtifactId::new([0x55; 32]),
            }),
            status: RemoteProofStatus::Requested,
        }
    }

    fn failed(reason: &str) -> RemoteProofStatus {
        RemoteProofStatus::Failed(RemoteProofFailureReason::Other(reason.to_owned()))
    }

    #[tokio::test]
    async fn complete_job_record_is_atomic_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let job = moho_job(42, 0xaa);

        {
            let raw = sled::open(dir.path()).unwrap();
            let store = SledProofDb::open(&raw).unwrap();
            store.create_remote_proof_job(job.clone()).await.unwrap();
            raw.flush().unwrap();
        }

        let raw = sled::open(dir.path()).unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        assert_eq!(
            store
                .get_active_remote_proof_job(job.proof_id)
                .await
                .unwrap(),
            Some(job.clone()),
        );
        assert_eq!(
            store.get_remote_proof_job(&job.remote_id).await.unwrap(),
            Some(job),
        );
    }

    #[tokio::test]
    async fn rejected_submission_leaves_neither_job_nor_active_index() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        let original = moho_job(1, 0xaa);
        store
            .create_remote_proof_job(original.clone())
            .await
            .unwrap();

        let conflicting = moho_job(2, 0xaa);
        assert!(matches!(
            store.create_remote_proof_job(conflicting.clone()).await,
            Err(RemoteProofJobError::DuplicateRemoteId(_))
        ));
        assert_eq!(
            store
                .get_active_remote_proof_job(conflicting.proof_id)
                .await
                .unwrap(),
            None,
        );
        assert_eq!(
            store
                .get_active_remote_proof_job(original.proof_id)
                .await
                .unwrap(),
            Some(original),
        );
    }

    #[tokio::test]
    async fn active_job_identity_cannot_be_reinterpreted_on_retry() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        let original = moho_job(42, 0xaa);
        store
            .create_remote_proof_job(original.clone())
            .await
            .unwrap();

        let mut changed_identity = moho_job(42, 0xbb);
        let ProofJobIdentity::Moho(identity) = &mut changed_identity.identity else {
            unreachable!()
        };
        identity.artifact_id = GuestArtifactId::new([0x99; 32]);

        assert!(matches!(
            store.create_remote_proof_job(changed_identity).await,
            Err(RemoteProofJobError::AlreadyActive { .. })
        ));
        assert_eq!(
            store
                .get_active_remote_proof_job(original.proof_id)
                .await
                .unwrap(),
            Some(original),
        );
    }

    #[tokio::test]
    async fn create_enforces_proof_kind_and_rejects_legacy_identity() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let store = SledProofDb::open(&raw).unwrap();

        let mut wrong_kind = moho_job(42, 0xaa);
        wrong_kind.proof_id = ProofId::Asm(L1Range::single(block(42)));
        assert!(matches!(
            store.create_remote_proof_job(wrong_kind).await,
            Err(RemoteProofJobError::InvalidJob(_))
        ));

        let mut legacy = moho_job(42, 0xbb);
        legacy.identity = ProofJobIdentity::LegacyUnqualifiedMoho;
        assert!(matches!(
            store.create_remote_proof_job(legacy).await,
            Err(RemoteProofJobError::InvalidJob(_))
        ));
    }

    #[tokio::test]
    async fn failed_attempt_is_auditable_and_late_update_cannot_clear_retry() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        let first = moho_job(42, 0xaa);
        let retry = moho_job(42, 0xbb);
        let failed_status = failed("first attempt failed");

        store.create_remote_proof_job(first.clone()).await.unwrap();
        store
            .finish_remote_proof_job(
                &first.remote_id,
                RemoteProofStatus::Requested,
                failed_status.clone(),
            )
            .await
            .unwrap();
        store.create_remote_proof_job(retry.clone()).await.unwrap();

        // Idempotent replay of the old terminal event does not touch the
        // replacement active index.
        store
            .finish_remote_proof_job(
                &first.remote_id,
                RemoteProofStatus::Requested,
                failed_status.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .get_active_remote_proof_job(retry.proof_id)
                .await
                .unwrap(),
            Some(retry),
        );

        let historical = store
            .get_remote_proof_job(&first.remote_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(historical.status, failed_status);
    }

    #[tokio::test]
    async fn stale_status_update_is_rejected_without_overwrite() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        let job = moho_job(42, 0xaa);
        store.create_remote_proof_job(job.clone()).await.unwrap();
        store
            .update_remote_proof_job_status(
                &job.remote_id,
                RemoteProofStatus::Requested,
                RemoteProofStatus::InProgress,
            )
            .await
            .unwrap();

        assert!(matches!(
            store
                .update_remote_proof_job_status(
                    &job.remote_id,
                    RemoteProofStatus::Requested,
                    RemoteProofStatus::InProgress,
                )
                .await,
            Err(RemoteProofJobError::StatusConflict { .. })
        ));
        assert_eq!(
            store
                .get_remote_proof_job(&job.remote_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            RemoteProofStatus::InProgress,
        );
    }

    #[tokio::test]
    async fn legacy_mapping_without_status_is_recovered_for_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let proof_id = ProofId::Asm(L1Range::single(block(42)));
        let remote_id = RemoteProofId(vec![0xaa]);

        {
            let raw = sled::open(dir.path()).unwrap();
            raw.open_tree("proof_to_remote")
                .unwrap()
                .insert(borsh::to_vec(&proof_id).unwrap(), remote_id.0.clone())
                .unwrap();
            raw.open_tree("remote_to_proof")
                .unwrap()
                .insert(remote_id.0.clone(), borsh::to_vec(&proof_id).unwrap())
                .unwrap();
            raw.flush().unwrap();
        }

        let raw = sled::open(dir.path()).unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        let recovered = store
            .get_active_remote_proof_job(proof_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.remote_id, remote_id);
        assert_eq!(recovered.status, RemoteProofStatus::Requested);
        assert_eq!(recovered.identity, ProofJobIdentity::LegacyUnqualifiedAsm);

        let qualified = ProofJobIdentity::Asm(AsmProofJobIdentity {
            predicate: PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![0x44; 32])
                .unwrap(),
            spec_id: AsmSpecId::V0,
            artifact_id: AsmArtifactId::new([0x55; 32]),
        });
        let rebound = store
            .bind_legacy_remote_proof_job(&remote_id, qualified.clone())
            .await
            .unwrap();
        assert_eq!(rebound.identity, qualified);

        let changed = ProofJobIdentity::Asm(AsmProofJobIdentity {
            predicate: PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![0x66; 32])
                .unwrap(),
            spec_id: AsmSpecId::V1,
            artifact_id: AsmArtifactId::new([0x77; 32]),
        });
        assert!(matches!(
            store
                .bind_legacy_remote_proof_job(&remote_id, changed)
                .await,
            Err(RemoteProofJobError::IdentityConflict(_))
        ));

        store
            .finish_remote_proof_job(
                &remote_id,
                RemoteProofStatus::Requested,
                RemoteProofStatus::Completed,
            )
            .await
            .unwrap();
        assert_eq!(
            crate::RemoteProofMappingDb::get_remote_proof_id(&store, proof_id)
                .await
                .unwrap(),
            None,
            "the retained legacy forward row must not reactivate a finished migrated job",
        );
        assert!(store.in_progress().unwrap().is_empty());
        assert!(matches!(
            store
                .bind_legacy_remote_proof_job(&remote_id, qualified)
                .await,
            Err(RemoteProofJobError::NotActive(_))
        ));
    }

    #[tokio::test]
    async fn completed_legacy_mapping_imports_as_history_instead_of_active_work() {
        let dir = tempfile::tempdir().unwrap();
        let commitment = block(42);
        let proof_id = ProofId::Moho(commitment);
        let remote_id = RemoteProofId(vec![0xaa]);

        {
            let raw = sled::open(dir.path()).unwrap();
            raw.open_tree("moho_proofs")
                .unwrap()
                .insert(encode_moho_key(&commitment), &[0u8])
                .unwrap();
            raw.open_tree("proof_to_remote")
                .unwrap()
                .insert(borsh::to_vec(&proof_id).unwrap(), remote_id.0.clone())
                .unwrap();
            raw.open_tree("remote_to_proof")
                .unwrap()
                .insert(remote_id.0.clone(), borsh::to_vec(&proof_id).unwrap())
                .unwrap();
            raw.flush().unwrap();
        }

        let raw = sled::open(dir.path()).unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        assert_eq!(
            store
                .get_remote_proof_job(&remote_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            RemoteProofStatus::Completed,
        );
        assert_eq!(
            store.get_active_remote_proof_job(proof_id).await.unwrap(),
            None,
        );
        assert_eq!(
            crate::RemoteProofMappingDb::get_remote_proof_id(&store, proof_id)
                .await
                .unwrap(),
            None,
            "a retained legacy mapping must not reactivate an already stored proof",
        );
        assert!(store.in_progress().unwrap().is_empty());
    }

    #[test]
    fn corrupt_legacy_row_returns_an_open_error_instead_of_panicking() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        raw.open_tree("proof_to_remote")
            .unwrap()
            .insert([0xff], &[0xaa])
            .unwrap();

        let error = SledProofDb::open(&raw).unwrap_err();
        assert!(error.to_string().contains("corrupt legacy forward ProofId"));
    }

    #[test]
    fn conflicting_legacy_rows_fail_instead_of_becoming_partially_active() {
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let forward = raw.open_tree("proof_to_remote").unwrap();
        let first = ProofId::Moho(block(41));
        let second = ProofId::Moho(block(42));
        let remote = [0xaa];
        forward
            .insert(borsh::to_vec(&first).unwrap(), &remote)
            .unwrap();
        forward
            .insert(borsh::to_vec(&second).unwrap(), &remote)
            .unwrap();

        let error = SledProofDb::open(&raw).unwrap_err();
        assert!(
            error.to_string().contains("partial job/index pair")
                || error.to_string().contains("conflicts with an existing job")
        );
    }
}
