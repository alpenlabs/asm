//! Service framework integration for ASM.

use std::marker;

use bitcoin::hashes::Hash;
use serde::{Deserialize, Serialize};
use strata_asm_common::AsmSpec;
use strata_btc_types::BlockHashExt;
use strata_identifiers::{Buf32, L1BlockCommitment};
use strata_service::{Response, Service, SyncService};
use tracing::*;

use crate::{AsmState, AsmWorkerServiceState, message::AsmWorkerMessage, traits::WorkerContext};

/// ASM service implementation using the service framework.
#[derive(Debug)]
pub struct AsmWorkerService<W, S> {
    _phantom: marker::PhantomData<(W, S)>,
}

impl<W, S> Service for AsmWorkerService<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    type State = AsmWorkerServiceState<W, S>;
    type Msg = AsmWorkerMessage;
    type Status = AsmWorkerStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        AsmWorkerStatus {
            is_initialized: true,
            cur_block: Some(state.blkid),
            cur_state: Some(state.anchor.clone()),
        }
    }
}

impl<W, S> SyncService for AsmWorkerService<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    // TODO(STR-1928): add tests.
    fn process_input(
        state: &mut AsmWorkerServiceState<W, S>,
        input: AsmWorkerMessage,
    ) -> anyhow::Result<Response> {
        match input {
            AsmWorkerMessage::SubmitBlock(incoming_block, completion) => {
                let result = process_block(state, &incoming_block);
                let should_exit = result.is_err();
                completion.send_blocking(result);
                if should_exit {
                    return Ok(Response::ShouldExit);
                }
            }
        }
        Ok(Response::Continue)
    }
}

/// Processes an L1 block through the ASM state transition.
fn process_block<W, S>(
    state: &mut AsmWorkerServiceState<W, S>,
    incoming_block: &L1BlockCommitment,
) -> crate::WorkerResult<()>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    let ctx = &state.context;

    // Handle pre-genesis: if the block is before genesis we don't care about it.
    let genesis_height = state.genesis_height();
    let height = incoming_block.height();
    if height < genesis_height as u32 {
        warn!(height, "ignoring unexpected L1 block before genesis");
        return Ok(());
    }

    // Traverse back the chain of l1 blocks until we find an l1 block which has AnchorState.
    // Remember all the blocks along the way and pass it (in the reverse order) to process.
    let pivot_span = debug_span!("asm.pivot_lookup",
        target_height = height,
        target_block = %incoming_block.blkid()
    );
    let pivot_span_guard = pivot_span.enter();

    let mut skipped_blocks = vec![];
    let mut pivot_block = *incoming_block;
    let mut pivot_anchor = ctx.get_anchor_state(&pivot_block);

    while pivot_anchor.is_err() && pivot_block.height() as u64 >= genesis_height {
        let block = ctx.get_l1_block(pivot_block.blkid())?;
        let parent_height = pivot_block.height() - 1;
        let parent_block_id =
            L1BlockCommitment::new(parent_height, block.header.prev_blockhash.to_l1_block_id());

        // Push the unprocessed block.
        skipped_blocks.push((block, pivot_block));

        // Update the loop state.
        pivot_anchor = ctx.get_anchor_state(&parent_block_id);
        pivot_block = parent_block_id;
    }

    // We reached the height before genesis (while traversing), but didn't find genesis state.
    if (pivot_block.height() as u64) < genesis_height {
        warn!("ASM hasn't found pivot anchor state at genesis.");
        return Err(crate::WorkerError::MissingGenesisState);
    }

    // Found pivot anchor state - our starting point.
    info!(%pivot_block,
        skipped_blocks = skipped_blocks.len(),
        "ASM found pivot anchor state"
    );

    // Drop pivot span guard before next phase
    drop(pivot_span_guard);

    // Special handling for genesis block - its anchor state was created during init
    // but its manifest wasn't (because Bitcoin block wasn't available yet).
    // We only store the manifest to L1 (for data consumers) but do NOT append it
    // to the external MMR. The internal compact MMR in AnchorState is
    // height-indexed: positions `0..=genesis_height` are prefilled with
    // sentinel leaves so that the first appended manifest (the block at
    // `genesis_height + 1`) lands at MMR leaf index `genesis_height + 1`.
    // Appending the genesis manifest would consume that slot and shift every
    // subsequent leaf one position past its L1 height.
    // Idempotency: skip if the genesis manifest already exists in the L1 database.
    if pivot_block.height() as u64 == genesis_height && !ctx.has_l1_manifest(pivot_block.blkid())? {
        let genesis_span = info_span!("asm.genesis_manifest",
            pivot_height = pivot_block.height(),
            pivot_block = %pivot_block.blkid()
        );
        let _genesis_guard = genesis_span.enter();
        // Fetch the genesis block (should work now since L1 reader processed it)
        let genesis_block = ctx.get_l1_block(pivot_block.blkid())?;

        // Compute wtxids_root and create manifest
        let wtxids_root: Buf32 = genesis_block
            .witness_root()
            .map(|root| root.as_raw_hash().to_byte_array())
            .unwrap_or_else(|| {
                genesis_block
                    .header
                    .merkle_root
                    .as_raw_hash()
                    .to_byte_array()
            })
            .into();

        let genesis_manifest = strata_asm_common::AsmManifest::new(
            pivot_block.height(),
            *pivot_block.blkid(),
            wtxids_root.into(),
            vec![], /* TODO(STR-2771): we shouldn't require a genesis manifest. The manifest
                     * should start from the block after genesis. */
        )
        .expect("empty genesis manifest is within capacity");

        ctx.store_l1_manifest(genesis_manifest)?;

        info!(%pivot_block, "Created genesis manifest");
    } // genesis_span drops here

    state.update_anchor_state(pivot_anchor.unwrap(), pivot_block);

    // Process the whole chain of unprocessed blocks, starting from older blocks till
    // incoming_block.
    for (block, block_id) in skipped_blocks.iter().rev() {
        let transition_span = debug_span!("asm.block_transition",
            height = block_id.height(),
            block_id = %block_id.blkid()
        );
        let _transition_guard = transition_span.enter();

        info!(%block_id, "ASM transition attempt");
        let (asm_stf_out, aux_data) = state.transition(block)?;

        let storage_span = debug_span!("asm.manifest_storage");
        let _storage_guard = storage_span.enter();

        // Extract manifest and compute its hash
        let manifest = asm_stf_out.manifest.clone();
        let manifest_hash = manifest.compute_hash();

        // Store manifest to L1 database (for chaintsn and other consumers)
        state.context.store_l1_manifest(manifest)?;

        // Append manifest hash to MMR database
        let leaf_index = state.context.append_manifest_to_mmr(manifest_hash.into())?;

        // Store auxiliary data for prover consumption
        state.context.store_aux_data(block_id, &aux_data)?;

        let new_state = AsmState::from_output(asm_stf_out);
        // Store and update anchor.
        state.context.store_anchor_state(block_id, &new_state)?;
        state.update_anchor_state(new_state, *block_id);

        info!(%block_id, %height, leaf_index, "ASM transition complete, manifest and state stored");
    } // transition_span drops here

    Ok(())
}

/// Status information for the ASM worker service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AsmWorkerStatus {
    pub is_initialized: bool,
    pub cur_block: Option<L1BlockCommitment>,
    pub cur_state: Option<AsmState>,
}

impl AsmWorkerStatus {
    /// Get the logs from the current ASM state.
    ///
    /// Returns an empty slice if the state is not initialized.
    pub fn logs(&self) -> &[strata_asm_common::AsmLogEntry] {
        self.cur_state
            .as_ref()
            .map(|s| s.logs().as_slice())
            .unwrap_or(&[])
    }
}
