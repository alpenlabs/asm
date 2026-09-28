//! Reconciliation of in-flight remote proofs.
//!
//! Each tick, the service polls every remote proof that was previously
//! submitted and reacts to status changes: completed proofs are verified and
//! persisted to the proof store, jobs that will not yield a proof are
//! discarded so the scheduler can submit the block again, and everything else
//! just has its stored status refreshed.

use strata_asm_prover_types::RemoteProofId;
use tracing::{debug, error, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost};

use crate::{
    AsmHostRegistry, ProverContext,
    errors::{ProverError, ProverResult},
    proof_store::{self, ProofSource},
    state::ProverServiceState,
    verify::ExpectedAttestation,
};

/// Polls all in-progress remote proofs and stores any that have completed.
pub(crate) async fn reconcile_active_proofs<C, H>(
    state: &mut ProverServiceState<C, H>,
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
            warn!(%remote_id, ?e, "failed to reconcile remote proof");
        }
    }
    Ok(())
}

/// Reconciles a single remote proof.
async fn reconcile_one<C, H>(
    state: &mut ProverServiceState<C, H>,
    remote_id: &RemoteProofId,
    old_status: &RemoteProofStatus,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let typed_id = to_typed_proof_id::<H>(remote_id)?;

    // Status polling is program-independent for the configured provider. Receipt
    // retrieval below must use the appropriate host to preserve program metadata.
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
            handle_completed(state, remote_id, &typed_id).await?;
        }
        RemoteProofStatus::Failed(reason) => {
            error!(%remote_id, %reason, "remote proof generation failed. discarding submission");
            discard_submission(&state.ctx, remote_id).await?;
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
async fn handle_completed<C, H>(
    state: &mut ProverServiceState<C, H>,
    remote_id: &RemoteProofId,
    typed_id: &H::ProofId,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let proof_id = state
        .ctx
        .get_proof_id(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to look up proof ID from remote ID", e))?
        .ok_or(ProverError::NotFound(
            "no mapping found for completed remote proof",
        ))?;

    // A receipt that is not a proof of this block tells us nothing the job
    // having failed outright would not, so treat it the same way and let the
    // scheduler prove the block again. Failing to read our own state is a
    // different problem and propagates instead.
    let verifier = state.input_builder.verifier();
    let expected = verifier.expected_attestation(&state.ctx, &proof_id).await?;
    let receipt = receipt_host(&state.asm, &state.moho, &expected)?
        .get_proof(typed_id)
        .await
        .map_err(ProverError::RemoteRetrieve)?;
    if let Err(e) = verifier.verify(&receipt, &expected) {
        error!(%proof_id, %remote_id, %e, "completed proof failed verification, discarding it");
        return discard_submission(&state.ctx, remote_id).await;
    }

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
    remote_id: &RemoteProofId,
) -> ProverResult<()> {
    let proof_id = ctx
        .get_proof_id(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to look up proof ID from remote ID", e))?;

    if let Some(proof_id) = proof_id {
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

/// Selects the retrieval host from the same authority used to verify the receipt.
///
/// SP1 retrieval stamps the host's program ID into receipt metadata, so sharing a
/// provider client does not make hosts interchangeable here.
fn receipt_host<'a, H>(
    asm: &'a AsmHostRegistry<H>,
    moho: &'a H,
    expected: &ExpectedAttestation,
) -> ProverResult<&'a H> {
    match expected {
        ExpectedAttestation::Step { predicate, .. } => Ok(asm.get(predicate)?.host()),
        ExpectedAttestation::Recursive(_) => Ok(moho),
    }
}

#[cfg(test)]
mod tests {
    use k256::schnorr::SigningKey;
    use moho_types::{
        MohoStateCommitment, RecursiveMohoAttestation, StateRefAttestation, StateReference,
        StepMohoAttestation,
    };
    use strata_asm_spec::StrataAsmSpec;
    use strata_predicate::PredicateKey;
    use zkaleido::ZkVmVkProvider;
    use zkaleido_native_adapter::NativeHost;

    use super::*;
    use crate::AsmProofHost;

    fn host(seed: u8) -> NativeHost {
        NativeHost::new(SigningKey::from_bytes(&[seed; 32]).unwrap(), |_| {})
    }

    fn endpoint(seed: u8) -> StateRefAttestation {
        StateRefAttestation::new(
            StateReference::new([seed; 32]),
            MohoStateCommitment::new([seed; 32]),
        )
    }

    #[test]
    fn asm_receipt_retrieval_uses_the_parent_authorized_host() {
        let asm = AsmProofHost::bind::<StrataAsmSpec>(host(1)).unwrap();
        let predicate = asm.descriptor().predicate().clone();
        let registry = AsmHostRegistry::new(vec![asm]).unwrap();
        let moho = host(2);
        let expected = ExpectedAttestation::Step {
            attestation: StepMohoAttestation::new(endpoint(1), endpoint(2)),
            predicate: predicate.clone(),
        };

        let selected = receipt_host(&registry, &moho, &expected).unwrap();
        assert_eq!(
            selected.vk().as_bytes(),
            registry.get(&predicate).unwrap().host().vk().as_bytes()
        );
        assert_ne!(selected.vk().as_bytes(), moho.vk().as_bytes());
    }

    #[test]
    fn moho_receipt_retrieval_uses_the_fixed_host() {
        let registry =
            AsmHostRegistry::new(vec![AsmProofHost::bind::<StrataAsmSpec>(host(1)).unwrap()])
                .unwrap();
        let moho = host(2);
        let expected =
            ExpectedAttestation::Recursive(RecursiveMohoAttestation::new(endpoint(0), endpoint(2)));

        let selected = receipt_host(&registry, &moho, &expected).unwrap();
        assert_eq!(selected.vk().as_bytes(), moho.vk().as_bytes());
    }

    #[test]
    fn missing_asm_host_does_not_fall_back_to_moho_for_retrieval() {
        let registry =
            AsmHostRegistry::new(vec![AsmProofHost::bind::<StrataAsmSpec>(host(1)).unwrap()])
                .unwrap();
        let expected = ExpectedAttestation::Step {
            attestation: StepMohoAttestation::new(endpoint(1), endpoint(2)),
            predicate: PredicateKey::always_accept(),
        };

        assert!(matches!(
            receipt_host(&registry, &host(2), &expected),
            Err(ProverError::UnknownArtifact(_))
        ));
    }
}
