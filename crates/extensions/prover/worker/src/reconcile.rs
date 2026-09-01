//! Reconciliation of in-flight remote proofs.
//!
//! Each tick, the service polls every remote proof that was previously
//! submitted and reacts to status changes: completed proofs are retrieved and
//! persisted to the proof store, failed proofs are dropped so the scheduler can
//! resubmit them, and everything else just has its stored status refreshed.

use std::error::Error as StdError;

use strata_asm_prover_storage::RemoteProofJobDb;
use strata_asm_prover_types::{
    AsmProofJobIdentity, ProofId, ProofJobIdentity, RemoteProofId, RemoteProofJob,
};
use tracing::{debug, error, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost};

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
    hosts::{AsmHost, AsmHosts},
    job_identity::validate_or_bind_job_identity,
    proof_store::{self, ProofSource},
    queue::PendingProofQueue,
    state::ProverServiceState,
};

/// Polls all in-progress remote proofs and stores any that have completed.
pub(crate) async fn reconcile_active_proofs<C, H>(
    state: &mut ProverServiceState<C, H>,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let active_jobs = state
        .ctx
        .get_all_active_remote_proof_jobs()
        .await
        .map_err(|e| ProverError::storage("failed to query active remote proof jobs", e))?;

    for job in active_jobs {
        let remote_id = job.remote_id.clone();
        if let Err(e) = reconcile_one(state, job).await {
            warn!(%remote_id, ?e, "failed to reconcile remote proof");
        }
    }
    Ok(())
}

/// Reconciles a single remote proof.
async fn reconcile_one<C, H>(
    state: &mut ProverServiceState<C, H>,
    job: RemoteProofJob,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let job = validate_or_bind_job_identity(
        &state.ctx,
        &state.input_builder,
        &state.asm,
        &state.moho_identity,
        job,
    )
    .await?;
    let remote_id = &job.remote_id;
    let old_status = &job.status;
    let typed_id = to_typed_proof_id::<H>(remote_id)?;

    // NOTE: Any host instance works here. `get_status` only requires a network
    // client and proof ID — not the ELF or proving key — so which artifact
    // produced the proof is irrelevant to asking about it.
    let new_status = state
        .asm
        .client()
        .get_status(&typed_id)
        .await
        .map_err(ProverError::RemoteStatus)?;

    if &new_status == old_status
        && !matches!(
            new_status,
            RemoteProofStatus::Completed | RemoteProofStatus::Failed(_)
        )
    {
        return Ok(());
    }

    debug!(%remote_id, ?old_status, ?new_status, "remote proof status changed");

    match &new_status {
        RemoteProofStatus::Completed => {
            handle_completed(state, &job, &typed_id).await?;
        }
        RemoteProofStatus::Failed(reason) => {
            error!(?remote_id, %reason, "remote proof generation failed");
            release_failed_proof(&state.ctx, &mut state.queue, &job, new_status).await?;
        }
        _ => {
            state
                .ctx
                .update_remote_proof_job_status(remote_id, old_status.clone(), new_status)
                .await
                .map_err(|e| ProverError::storage("failed to update remote proof job", e))?;
        }
    }
    Ok(())
}

/// Releases a failed job from deduplication and restores its local task.
///
/// The failed status and active-index removal are one atomic storage transition;
/// the complete record remains as audit history.
async fn release_failed_proof<C>(
    ctx: &C,
    queue: &mut PendingProofQueue,
    job: &RemoteProofJob,
    failed_status: RemoteProofStatus,
) -> ProverResult<ProofId>
where
    C: RemoteProofJobDb + Sync,
    <C as RemoteProofJobDb>::Error: StdError + Send + Sync + 'static,
{
    let proof_id = job.proof_id;
    ctx.finish_remote_proof_job(&job.remote_id, job.status.clone(), failed_status)
        .await
        .map_err(|e| ProverError::storage("failed to finish failed remote proof job", e))?;

    // Submission removed the proof from the queue. Re-enqueue before this
    // reconcile pass returns so the same tick's scheduler can retry even an
    // isolated latest-tip Moho job with no dependent task to rediscover it.
    queue.enqueue(proof_id);
    Ok(proof_id)
}

/// Retrieves a completed proof, stores it in the proof store, and advances the
/// proven frontier surfaced through the service status.
async fn handle_completed<C, H>(
    state: &mut ProverServiceState<C, H>,
    job: &RemoteProofJob,
    typed_id: &H::ProofId,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let proof_id = job.proof_id;

    // Unlike status polling, SP1 proof retrieval is artifact-sensitive: the
    // adapter constructs the receipt metadata with the calling host's program
    // ID. Recover the same route used at submission rather than silently
    // labeling every receipt with the first ASM artifact.
    let host = completed_proof_host(&state.asm, &state.moho, &proof_id, &job.identity)?;
    let receipt = host
        .get_proof(typed_id)
        .await
        .map_err(ProverError::RemoteRetrieve)?;

    proof_store::store_completed_proof(&state.ctx, proof_id, receipt, ProofSource::Backend).await?;

    state.advance_proven(&proof_id).await?;

    state
        .ctx
        .finish_remote_proof_job(
            &job.remote_id,
            job.status.clone(),
            RemoteProofStatus::Completed,
        )
        .await
        .map_err(|e| ProverError::storage("failed to finish completed remote proof job", e))?;

    Ok(())
}

/// Selects the host whose program metadata belongs on a completed receipt.
///
/// The ASM route comes from the immutable identity stored at submission, after
/// [`validate_or_bind_job_identity`] checked it against authenticated state and
/// this release's qualified artifacts.
fn completed_proof_host<'a, H>(
    asm: &'a AsmHosts<H>,
    moho: &'a H,
    proof_id: &ProofId,
    identity: &ProofJobIdentity,
) -> ProverResult<&'a H> {
    match (proof_id, identity) {
        (ProofId::Asm(_), ProofJobIdentity::Asm(expected)) => {
            let artifact = asm
                .resolve_artifact_id(&expected.artifact_id)
                .ok_or_else(|| ProverError::MissingAsmArtifact {
                    predicate: format!("{:?}", expected.predicate),
                })?;
            if artifact.predicate != expected.predicate || artifact.spec_id != expected.spec_id {
                return Err(identity_mismatch(proof_id, identity, artifact));
            }
            Ok(&artifact.host)
        }
        (ProofId::Moho(_), ProofJobIdentity::Moho(_)) => Ok(moho),
        _ => Err(ProverError::ProofJobIdentityMismatch {
            proof_id: proof_id.to_string(),
            stored: format!("{identity:?}"),
            expected: "identity matching the proof kind".to_owned(),
        }),
    }
}

fn identity_mismatch<H>(
    proof_id: &ProofId,
    stored: &ProofJobIdentity,
    artifact: &AsmHost<H>,
) -> ProverError {
    let expected = ProofJobIdentity::Asm(AsmProofJobIdentity {
        predicate: artifact.predicate.clone(),
        spec_id: artifact.spec_id,
        artifact_id: artifact.artifact_id,
    });
    ProverError::ProofJobIdentityMismatch {
        proof_id: proof_id.to_string(),
        stored: format!("{stored:?}"),
        expected: format!("{expected:?}"),
    }
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<H: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> ProverResult<H::ProofId> {
    H::ProofId::try_from(remote_id.0.clone()).map_err(|_| ProverError::RemoteIdDecode)
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{AsmArtifactId, AsmSpecId, GuestArtifactId};
    use strata_asm_prover_storage::{RemoteProofJobDb, SledProofDb};
    use strata_asm_prover_types::{L1Range, MohoProofJobIdentity};
    use strata_identifiers::{L1BlockCommitment, L1BlockId};
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use zkaleido::RemoteProofFailureReason;

    use super::*;
    use crate::hosts::ArtifactQualification;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    fn block(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    fn hosts() -> AsmHosts<&'static str> {
        AsmHosts::new(
            vec![
                AsmHost {
                    artifact_id: AsmArtifactId::new([1; 32]),
                    spec_id: AsmSpecId::V0,
                    predicate: predicate(1),
                    host: "baseline",
                },
                AsmHost {
                    artifact_id: AsmArtifactId::new([2; 32]),
                    spec_id: AsmSpecId::V1,
                    predicate: predicate(2),
                    host: "successor",
                },
            ],
            ArtifactQualification::Release,
        )
        .expect("valid artifact set")
    }

    fn asm_identity(seed: u8, spec_id: AsmSpecId) -> ProofJobIdentity {
        ProofJobIdentity::Asm(AsmProofJobIdentity {
            predicate: predicate(seed),
            spec_id,
            artifact_id: AsmArtifactId::new([seed; 32]),
        })
    }

    fn moho_identity() -> ProofJobIdentity {
        ProofJobIdentity::Moho(MohoProofJobIdentity {
            predicate: predicate(9),
            artifact_id: GuestArtifactId::new([9; 32]),
        })
    }

    #[test]
    fn completed_asm_proof_uses_its_predicate_selected_artifact() {
        let asm = hosts();
        let proof_id = ProofId::Asm(L1Range::single(block(1)));

        assert_eq!(
            completed_proof_host(&asm, &"moho", &proof_id, &asm_identity(2, AsmSpecId::V1),)
                .expect("successor artifact is loaded"),
            &"successor",
        );
    }

    #[test]
    fn completed_asm_proof_rejects_reinterpreted_artifact_metadata() {
        let asm = hosts();
        let proof_id = ProofId::Asm(L1Range::single(block(1)));
        let mut identity = asm_identity(2, AsmSpecId::V1);
        let ProofJobIdentity::Asm(stored) = &mut identity else {
            unreachable!()
        };
        stored.spec_id = AsmSpecId::V0;

        assert!(matches!(
            completed_proof_host(&asm, &"moho", &proof_id, &identity),
            Err(ProverError::ProofJobIdentityMismatch { .. })
        ));
    }

    #[test]
    fn completed_moho_proof_uses_the_moho_host() {
        let asm = hosts();
        let proof_id = ProofId::Moho(block(1));

        assert_eq!(
            completed_proof_host(&asm, &"moho", &proof_id, &moho_identity())
                .expect("moho host is always configured"),
            &"moho",
        );
    }

    #[tokio::test]
    async fn failed_latest_tip_moho_proof_is_released_and_requeued_for_same_cycle_retry() {
        let proof_id = ProofId::Moho(block(42));
        let remote_id = RemoteProofId(vec![0xfa]);
        let raw = sled::Config::new().temporary(true).open().unwrap();
        let store = SledProofDb::open(&raw).unwrap();
        let job = RemoteProofJob {
            proof_id,
            remote_id: remote_id.clone(),
            identity: moho_identity(),
            status: RemoteProofStatus::Requested,
        };
        store.create_remote_proof_job(job.clone()).await.unwrap();
        let mut queue = PendingProofQueue::new();
        let failure = RemoteProofStatus::Failed(RemoteProofFailureReason::Other(
            "retryable test failure".to_owned(),
        ));

        assert_eq!(
            release_failed_proof(&store, &mut queue, &job, failure.clone())
                .await
                .unwrap(),
            proof_id,
        );

        assert_eq!(
            store.get_active_remote_proof_job(proof_id).await.unwrap(),
            None,
        );
        let historical = store
            .get_remote_proof_job(&remote_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(historical.proof_id, proof_id);
        assert_eq!(historical.status, failure);
        assert_eq!(queue.dequeue_one(), Some(proof_id));
        assert!(queue.is_empty());
    }
}
