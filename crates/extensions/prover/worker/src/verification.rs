//! Validation shared by remote completions and peer-fetched receipts.
use strata_asm_prover_types::ProofId;
use tokio::task::spawn_blocking;
use zkaleido::{ProofReceiptWithMetadata, ZkVmTypedVerifier};

use crate::{
    AsmHostLoader, AsmHostRegistry, InputBuilder, ProverContext, ProverError, ProverResult,
};

pub(crate) async fn verify_receipt<C: ProverContext, L: AsmHostLoader>(
    ctx: &C,
    input: &InputBuilder,
    hosts: &mut AsmHostRegistry<L>,
    moho: &L::Host,
    id: ProofId,
    receipt: &ProofReceiptWithMetadata,
) -> ProverResult<()> {
    // Reject mismatched claims before loading a host or verifying the proof.
    input
        .validate_output(ctx, id, receipt.receipt().public_values().as_bytes())
        .await?;

    let host = match id {
        ProofId::Asm(_) => {
            let predicate = input.expected_predicate(ctx, id).await?;
            hosts.load(&predicate).await?.host().clone()
        }
        ProofId::Moho(_) => moho.clone(),
    };
    let proof = receipt.clone();
    spawn_blocking(move || host.verify(&proof))
        .await
        .map_err(|e| ProverError::backend("proof verification task failed", e))?
        .map_err(ProverError::InvalidProof)?;
    Ok(())
}
