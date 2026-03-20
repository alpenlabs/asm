//! Proof DB helpers that dispatch on [`ProofId`] variants.
//!
//! These free functions encapsulate the match-on-ProofId pattern, keeping the
//! orchestrator focused on coordination logic.

use anyhow::{Context, Result};
use strata_asm_proof_db::{ProofDb, SledProofDb};
use strata_asm_proof_types::{AsmProof, MohoProof, ProofId};
use tracing::info;
use zkaleido::ProofReceiptWithMetadata;

/// Returns `true` if the proof already exists in the local proof DB.
pub(crate) async fn proof_exists(db: &SledProofDb, proof_id: &ProofId) -> Result<bool> {
    match proof_id {
        ProofId::Asm(range) => {
            let exists = db
                .get_asm_proof(*range)
                .await
                .context("failed to check ASM proof")?
                .is_some();
            Ok(exists)
        }
        ProofId::Moho(commitment) => {
            let exists = db
                .get_moho_proof(*commitment)
                .await
                .context("failed to check Moho proof")?
                .is_some();
            Ok(exists)
        }
    }
}

/// Stores a completed proof receipt in the appropriate DB table.
pub(crate) async fn store_completed_proof(
    db: &SledProofDb,
    proof_id: ProofId,
    receipt: ProofReceiptWithMetadata,
) -> Result<()> {
    match proof_id {
        ProofId::Asm(range) => {
            info!(?range, "storing completed ASM proof");
            db.store_asm_proof(range, AsmProof(receipt))
                .await
                .context("failed to store ASM proof")?;
        }
        ProofId::Moho(commitment) => {
            info!(?commitment, "storing completed Moho proof");
            db.store_moho_proof(commitment, MohoProof(receipt))
                .await
                .context("failed to store Moho proof")?;
        }
    }
    Ok(())
}
