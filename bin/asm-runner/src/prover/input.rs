//! Input preparation for proof generation.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type.

use std::sync::Arc;

use anyhow::{Context, Result};
use asm_storage::AsmStateDb;
use bitcoind_async_client::{Client, traits::Reader};
use moho_runtime_impl::RuntimeInput;
use moho_runtime_interface::MohoProgram;
use ssz::Encode;
use strata_asm_proof_impl::moho_program::{input::AsmStepInput, program::AsmStfProgram};
use strata_asm_proof_types::L1Range;
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_btc_verification::{self, TxidInclusionProof};
use strata_identifiers::L1BlockCommitment;

/// Builds [`RuntimeInput`] for proof generation, dispatching by proof type.
pub(crate) struct InputBuilder {
    state_db: Arc<AsmStateDb>,
    bitcoin_client: Arc<Client>,
}

impl InputBuilder {
    pub(crate) fn new(state_db: Arc<AsmStateDb>, bitcoin_client: Arc<Client>) -> Self {
        Self {
            state_db,
            bitcoin_client,
        }
    }

    /// Builds the [`RuntimeInput`] for a single-block ASM proof.
    ///
    /// This fetches the Bitcoin block and auxiliary data, reconstructs the
    /// pre-state, and assembles the input the ZkVM program expects.
    pub(crate) async fn build_asm_runtime_input(&self, range: &L1Range) -> Result<RuntimeInput> {
        let commitment = range.start();

        // 1. Fetch the Bitcoin block.
        let block_hash = commitment.blkid().to_block_hash();
        let block = self
            .bitcoin_client
            .get_block(&block_hash)
            .await
            .context("failed to fetch Bitcoin block")?;

        // 2. Fetch the auxiliary data stored during STF execution.
        let aux_data = self
            .state_db
            .get_aux_data(&commitment)
            .context("failed to fetch aux data")?
            .context("aux data not found for block")?;

        let coinbase_inclusion_proof = match block.witness_root() {
            Some(_) => Some(TxidInclusionProof::generate(&block.txdata, 0)),
            None => None,
        };

        // 3. Build the step input.
        let step_input = AsmStepInput::new(block.clone(), aux_data, coinbase_inclusion_proof);

        // 4. Fetch the pre-state (anchor state for the parent block).
        let parent_hash = block.header.prev_blockhash;
        let parent_height = commitment
            .height()
            .checked_sub(1)
            .context("cannot generate ASM proof for height 0 — no parent block")?;
        let parent_commitment = L1BlockCommitment::new(parent_height, parent_hash.to_l1_block_id());

        let asm_state = self
            .state_db
            .get(&parent_commitment)
            .context("failed to fetch parent anchor state")?
            .context("parent anchor state not found")?;
        let anchor_state = asm_state.state();

        // 5. Compute the Moho pre-state from the anchor state.
        let inner_state_commitment = AsmStfProgram::compute_state_commitment(anchor_state);
        let moho_pre_state = moho_types::MohoState::new(
            inner_state_commitment,
            strata_predicate::PredicateKey::always_accept(),
            moho_types::ExportState::new(vec![]),
        );

        // 6. Build RuntimeInput.
        let runtime_input = RuntimeInput::new(
            moho_pre_state,
            anchor_state.as_ssz_bytes(),
            step_input.as_ssz_bytes(),
        );

        Ok(runtime_input)
    }
}
