//! Reconciliation of in-flight remote proofs.
//!
//! Each tick, the service polls every remote proof that was previously
//! submitted and reacts to status changes: completed proofs are retrieved and
//! persisted to the proof store, jobs that will not yield a proof are
//! discarded so the scheduler can submit the block again, and everything else
//! just has its stored status refreshed.

use strata_asm_prover_types::{ProofId, RemoteProofId};
use tracing::{debug, error, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost, ZkVmRemoteProver};

use crate::{
    AsmHostLoader, ProverContext,
    errors::{ProverError, ProverResult},
    proof_store::{self, ProofSource},
    state::ProverServiceState,
    verification::verify_receipt,
};

/// Polls all in-progress remote proofs and stores any that have completed.
pub(crate) async fn reconcile_active_proofs<C, L>(
    state: &mut ProverServiceState<C, L>,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    L: AsmHostLoader,
{
    let in_progress = state
        .ctx
        .get_all_in_progress()
        .await
        .map_err(|e| ProverError::storage("failed to query in-progress proofs", e))?;

    for (remote_id, old_status) in in_progress {
        if let Err(e) = reconcile_one(state, &remote_id, &old_status).await {
            if e.is_terminal() {
                return Err(e);
            }
            warn!(%remote_id, ?e, "failed to reconcile remote proof");
        }
    }
    Ok(())
}

/// Reconciles a single remote proof.
async fn reconcile_one<C, L>(
    state: &mut ProverServiceState<C, L>,
    remote_id: &RemoteProofId,
    old_status: &RemoteProofStatus,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    L: AsmHostLoader,
{
    let typed_id = to_typed_proof_id::<L::Host>(remote_id)?;

    let proof_id = resolve_pending_proof(state, remote_id).await?;
    // One provider per node: the fixed Moho host supplies its network client.
    let new_status = state
        .moho
        .get_status(&typed_id)
        .await
        .map_err(ProverError::RemoteStatus)?;

    if &new_status == old_status {
        return Ok(());
    }

    debug!(%remote_id, ?old_status, ?new_status, "remote proof status changed");

    match &new_status {
        RemoteProofStatus::Completed => {
            handle_completed(state, proof_id, remote_id, &typed_id).await?;
        }
        RemoteProofStatus::Failed(reason) => {
            error!(%remote_id, %reason, "remote proof generation failed. discarding submission");
            discard_submission(&state.ctx, proof_id, remote_id).await?;
            state.queue.enqueue(proof_id);
        }
        _ => {
            state
                .ctx
                .update_status(remote_id, new_status)
                .await
                .map_err(|e| ProverError::storage("failed to update proof status", e))?;
        }
    }
    Ok(())
}

/// Retrieves a completed proof, stores it in the proof store, and advances the
/// proven frontier surfaced through the service status.
async fn handle_completed<C, L>(
    state: &mut ProverServiceState<C, L>,
    proof_id: ProofId,
    remote_id: &RemoteProofId,
    typed_id: &<L::Host as ZkVmRemoteProver>::ProofId,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    L: AsmHostLoader,
{
    let receipt = state
        .moho
        .get_proof(typed_id)
        .await
        .map_err(ProverError::RemoteRetrieve)?;

    verify_receipt(
        &state.ctx,
        &state.input_builder,
        &mut state.asm,
        &state.moho,
        proof_id,
        &receipt,
    )
    .await?;
    proof_store::store_completed_proof(&state.ctx, proof_id, receipt, ProofSource::Backend).await?;

    state.advance_proven(&proof_id);

    state
        .ctx
        .remove_status(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to remove completed proof status", e))?;

    Ok(())
}

/// Forgets a remote job that will never yield a proof, so its proof can be
/// submitted again.
///
/// Dropping the status entry alone is not enough. The proof's mapping is what
/// [`schedule`](crate::schedule) reads to decide the proof is already in
/// flight, and it is durable — leaving it behind means the block is never
/// proven again, not even after a restart.
async fn discard_submission<C: ProverContext>(
    ctx: &C,
    proof_id: ProofId,
    remote_id: &RemoteProofId,
) -> ProverResult<()> {
    if ctx
        .get_remote_proof_id(proof_id)
        .await
        .map_err(|e| ProverError::storage("failed to read current submission", e))?
        .as_ref()
        == Some(remote_id)
    {
        ctx.clear_remote_proof_id(proof_id)
            .await
            .map_err(|e| ProverError::storage("failed to clear remote proof mapping", e))?;
    }

    ctx.remove_status(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to remove proof status", e))?;

    Ok(())
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<H: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> ProverResult<H::ProofId> {
    H::ProofId::try_from(remote_id.0.clone()).map_err(|_| ProverError::RemoteIdDecode)
}

/// Resolves a pending job and checks that its required program is available.
pub(crate) async fn resolve_pending_proof<C, L>(
    state: &ProverServiceState<C, L>,
    remote_id: &RemoteProofId,
) -> ProverResult<ProofId>
where
    C: ProverContext + Send + Sync,
    L: AsmHostLoader,
{
    let proof_id = state
        .ctx
        .get_proof_id(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to read remote proof mapping", e))?
        .ok_or(ProverError::MissingProofMapping)?;
    // ASM authority comes from this job's persisted parent, even after a newer
    // spec activates. The node uses one fixed Moho program across restarts.
    if matches!(proof_id, ProofId::Asm(_)) {
        let predicate = state
            .input_builder
            .expected_predicate(&state.ctx, proof_id)
            .await?;
        state.asm.spec_id(&predicate)?;
    }
    Ok(proof_id)
}
