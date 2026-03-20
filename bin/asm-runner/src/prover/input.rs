//! Input preparation for proof generation.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type.

use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoind_async_client::{Client, traits::Reader};
use moho_runtime_impl::RuntimeInput;
use moho_runtime_interface::MohoProgram;
use strata_asm_proof_impl::moho_program::{
    input::{AsmStepInput, L1Block},
    program::AsmStfProgram,
};
use strata_asm_proof_types::L1Range;
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_identifiers::L1BlockCommitment;
use strata_storage::AsmStateManager;

/// Builds [`RuntimeInput`] for proof generation, dispatching by proof type.
pub(crate) struct InputBuilder {
    asm_manager: Arc<AsmStateManager>,
    bitcoin_client: Arc<Client>,
}

impl InputBuilder {
    pub(crate) fn new(asm_manager: Arc<AsmStateManager>, bitcoin_client: Arc<Client>) -> Self {
        Self {
            asm_manager,
            bitcoin_client,
        }
    }

    /// Returns `true` if the ASM state required for proving `range` is available.
    ///
    /// Checks whether `aux_data` exists for the start commitment. This is a
    /// lightweight, synchronous check against the local database.
    ///
    /// # Temporary workaround
    ///
    /// This check is necessary because `AsmWorkerHandle::submit_block(_async)` only
    /// guarantees enqueueing — it does not provide processing-completion semantics.
    /// The orchestrator therefore cannot assume that state is available immediately
    /// after a block is submitted to the worker.
    ///
    /// This workaround is not required after STR-2596
    /// (<https://alpenlabs.atlassian.net/browse/STR-2596>), which will make
    /// `submit_block` / `submit_block_async` return `Ok(())` only after block
    /// processing completes successfully (or `Err(...)` on failure).
    pub(crate) fn is_asm_proof_ready(&self, range: &L1Range) -> bool {
        matches!(self.asm_manager.get_aux_data(range.start()), Ok(Some(_)))
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
            .asm_manager
            .get_aux_data(commitment)
            .context("failed to fetch aux data")?
            .context("aux data not found for block")?;

        // 3. Build the step input.
        let step_input = AsmStepInput {
            block: L1Block(block.clone()),
            aux_data,
        };

        // 4. Fetch the pre-state (anchor state for the parent block).
        let parent_hash = block.header.prev_blockhash;
        let parent_height = commitment
            .height()
            .checked_sub(1)
            .context("cannot generate ASM proof for height 0 — no parent block")?;
        let parent_commitment = L1BlockCommitment::new(parent_height, parent_hash.to_l1_block_id());

        let asm_state = self
            .asm_manager
            .get_state(parent_commitment)
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
            borsh::to_vec(anchor_state).context("failed to borsh-encode anchor state")?,
            borsh::to_vec(&step_input).context("failed to borsh-encode step input")?,
        );

        Ok(runtime_input)
    }
}
