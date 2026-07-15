//! Reconciliation of in-flight remote proofs.
//!
//! Each tick, the service polls every remote proof that was previously
//! submitted and reacts to status changes: completed proofs are retrieved and
//! persisted to the proof store, failed proofs are dropped so the scheduler can
//! resubmit them, and everything else just has its stored status refreshed.

use strata_asm_prover_types::RemoteProofId;
use tracing::{debug, error, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost};

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
    proof_store,
    state::ProverServiceState,
};

/// Polls all in-progress remote proofs and stores any that have completed.
pub(crate) async fn reconcile_active_proofs<C, H>(
    state: &ProverServiceState<C, H>,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let in_progress = state
        .ctx
        .get_all_in_progress()
        .await
        .map_err(|e| ProverError::storage("failed to query in-progress proofs", e))?;

    for (remote_id, old_status) in in_progress {
        if let Err(e) = reconcile_one(state, &remote_id, &old_status).await {
            warn!(?remote_id, ?e, "failed to reconcile remote proof");
        }
    }
    Ok(())
}

/// Reconciles a single remote proof.
async fn reconcile_one<C, H>(
    state: &ProverServiceState<C, H>,
    remote_id: &RemoteProofId,
    old_status: &RemoteProofStatus,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let typed_id = to_typed_proof_id::<H>(remote_id)?;

    // NOTE: We use `state.asm` here but this could be any host instance.
    // `get_status` only requires a network client and proof ID — not the ELF or
    // proving key. Both hosts share the same concrete type `H`, so either works.
    let new_status = state
        .asm
        .get_status(&typed_id)
        .await
        .map_err(ProverError::RemoteStatus)?;

    if &new_status == old_status {
        return Ok(());
    }

    debug!(%remote_id, ?old_status, ?new_status, "remote proof status changed");

    match &new_status {
        RemoteProofStatus::Completed => {
            handle_completed(state, remote_id, &typed_id).await?;
        }
        RemoteProofStatus::Failed(reason) => {
            error!(?remote_id, %reason, "remote proof generation failed");
            state
                .ctx
                .remove(remote_id)
                .await
                .map_err(|e| ProverError::storage("failed to remove failed proof status", e))?;
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

/// Retrieves a completed proof and stores it in the proof store.
async fn handle_completed<C, H>(
    state: &ProverServiceState<C, H>,
    remote_id: &RemoteProofId,
    typed_id: &H::ProofId,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    // NOTE: As above, `get_proof` only needs a network client and the proof ID,
    // so `state.asm` works for proofs produced by either host.
    let receipt = state
        .asm
        .get_proof(typed_id)
        .await
        .map_err(ProverError::RemoteRetrieve)?;

    let proof_id = state
        .ctx
        .get_proof_id(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to look up proof ID from remote ID", e))?
        .ok_or(ProverError::NotFound(
            "no mapping found for completed remote proof",
        ))?;

    proof_store::store_completed_proof(&state.ctx, proof_id, receipt).await?;

    state
        .ctx
        .remove(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to remove completed proof status", e))?;

    Ok(())
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<H: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> ProverResult<H::ProofId> {
    H::ProofId::try_from(remote_id.0.clone()).map_err(|_| ProverError::RemoteIdDecode)
}
