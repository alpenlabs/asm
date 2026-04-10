//! The `asm_stf` crate implements the core Anchor State Machine state transition function (STF). It
//! glues together block‐level validation, a set of pluggable subprotocols, and the global chain
//! view into a single deterministic state transition.

use bitcoin::Block;
use ssz_types::VariableList;
use strata_asm_common::{
    AnchorState, AsmError, AsmManifest, AsmResult, AsmSpec, AuxData, ChainViewState,
    VerifiedAuxData,
};
use strata_btc_verification::{TxidInclusionProof, check_block_integrity};

use crate::{
    group_txs_by_subprotocol,
    manager::SubprotoManager,
    stage::{FinishStage, LoaderStage, ProcessStage},
    types::AsmStfOutput,
};

/// Computes the next AnchorState by applying the Anchor State Machine (ASM) state transition
/// function (STF) to the given previous state and new L1 block.
///
/// This function performs the main ASM state transition by validating block integrity (merkle root,
/// witness commitment) and header continuity, loading subprotocols with auxiliary input data,
/// processing protocol-specific transactions, handling inter-protocol communication, and
/// constructing the final state with logs.
pub fn compute_asm_transition<S: AsmSpec>(
    spec: &S,
    pre_state: &AnchorState,
    block: &Block,
    aux_data: &AuxData,
    coinbase_inclusion_proof: Option<&TxidInclusionProof>,
) -> AsmResult<AsmStfOutput> {
    // 1. Validate that the block body merkle is consistent with the header.
    // Returns the witness txids root (segwit) or txids root (legacy) for use below.
    let wtxids_root = check_block_integrity(block, coinbase_inclusion_proof)?;

    // 2. Validate and update PoW header continuity for the new block.
    // This ensures the block header follows proper Bitcoin consensus rules and chain continuity.
    let (mut pow_state, mut history_accumulator) = pre_state.chain_view.clone().into_parts();
    pow_state
        .check_and_update(&block.header)
        .map_err(AsmError::InvalidL1Header)?;

    let verified_aux_data =
        VerifiedAuxData::try_new(aux_data, &pre_state.chain_view.history_accumulator)?;

    // After `check_and_update`, `last_verified_block` points to the block we
    // just validated — i.e. the L1 block whose transactions we are about to
    // feed into subprotocols.
    let current_l1ref = &pow_state.last_verified_block;

    // 3. Restructure the raw input to be formatted according to what we want.
    let protocol_txs = group_txs_by_subprotocol(pre_state.magic(), &block.txdata);

    let mut manager = SubprotoManager::new();

    // 4. LOAD: Initialize each subprotocol in the subproto manager.
    let mut loader = LoaderStage::new(&mut manager, pre_state);
    spec.call_subprotocols(&mut loader);

    // 5. PROCESS: Feed each subprotocol its filtered transactions for execution.
    // This stage performs the actual state transitions for each subprotocol.
    let mut process_stage =
        ProcessStage::new(&mut manager, current_l1ref, protocol_txs, verified_aux_data);
    spec.call_subprotocols(&mut process_stage);

    // 6. FINISH: Allow each subprotocol to process buffered inter-protocol messages.
    // This stage handles cross-protocol communication and finalizes state changes.
    // TODO(STR-0007): probably will have change this to repeat the interproto message
    // processing phase until we have no more messages to deliver, or some
    // bounded number of times
    let mut finish_stage = FinishStage::new(&mut manager, &pow_state.last_verified_block);
    spec.call_subprotocols(&mut finish_stage);

    // 7. Construct the manifest with the logs.
    let (sections, logs) = manager.export_sections_and_logs()?;
    let manifest = AsmManifest::new(
        current_l1ref.height(),
        *current_l1ref.blkid(),
        wtxids_root.into(),
        logs,
    )?;

    // 8. Append the manifest to the history accumulator
    history_accumulator.add_manifest(&manifest)?;

    // 9. Construct the final `AnchorState` and output.
    let chain_view = ChainViewState {
        pow_state,
        history_accumulator,
    };
    let state = AnchorState {
        magic: pre_state.magic,
        chain_view,
        sections: VariableList::new(sections).map_err(AsmError::TooManySections)?,
    };
    let output = AsmStfOutput { state, manifest };
    Ok(output)
}
