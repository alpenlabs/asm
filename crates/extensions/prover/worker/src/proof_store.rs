//! Proof-store helpers that dispatch on [`ProofId`] variants.
//!
//! These free functions encapsulate the match-on-ProofId pattern, keeping the
//! orchestrator focused on coordination logic. They operate through the
//! [`ProofDb`] surface of the [`ProverContext`].

use strata_asm_prover_types::{AsmProof, MohoProof, ProofId};
use tracing::info;
use zkaleido::ProofReceiptWithMetadata;

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
};

/// Returns `true` if the proof already exists in the local proof store.
pub(crate) async fn proof_exists<C: ProverContext>(
    ctx: &C,
    proof_id: &ProofId,
) -> ProverResult<bool> {
    match proof_id {
        ProofId::Asm(range) => {
            let exists = ctx
                .get_asm_proof(*range)
                .await
                .map_err(|e| ProverError::storage("failed to check ASM proof", e))?
                .is_some();
            Ok(exists)
        }
        ProofId::Moho(commitment) => {
            let exists = ctx
                .get_moho_proof(*commitment)
                .await
                .map_err(|e| ProverError::storage("failed to check Moho proof", e))?
                .is_some();
            Ok(exists)
        }
    }
}

/// Stores a completed proof receipt in the appropriate proof-store table.
pub(crate) async fn store_completed_proof<C: ProverContext>(
    ctx: &C,
    proof_id: ProofId,
    receipt: ProofReceiptWithMetadata,
) -> ProverResult<()> {
    match proof_id {
        ProofId::Asm(range) => {
            info!(?range, "storing completed ASM proof");
            ctx.store_asm_proof(range, AsmProof(receipt))
                .await
                .map_err(|e| ProverError::storage("failed to store ASM proof", e))?;
        }
        ProofId::Moho(commitment) => {
            info!(?commitment, "storing completed Moho proof");
            ctx.store_moho_proof(commitment, MohoProof(receipt))
                .await
                .map_err(|e| ProverError::storage("failed to store Moho proof", e))?;
        }
    }
    Ok(())
}
