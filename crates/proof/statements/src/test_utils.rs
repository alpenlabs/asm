//! Test utility constructors for ASM STF proof inputs/specs.
//!
//! This module is intended for integration binaries/tests that need a known-good
//! `RuntimeInput`/`StrataAsmSpec` pair for exercising the proof program.

use bitcoin::Block;
use moho_runtime_impl::RuntimeInput;
use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState};
use ssz::Encode;
use strata_asm_common::{AnchorState, AuxData};
use strata_asm_params::AsmParams;
use strata_asm_spec::{construct_genesis_state, StrataAsmSpec};
use strata_btc_types::BlockHashExt;
use strata_btc_verification::{L1Anchor, TxidInclusionProof};
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_test_utils_arb::ArbitraryGenerator;
use strata_test_utils_btc::BtcMainnetSegment;

use crate::moho_program::{input::AsmStepInput, program::AsmStfProgram};

/// Creates a single-step input from a fixed test Bitcoin block.
pub fn create_asm_step_input() -> AsmStepInput {
    let block = BtcMainnetSegment::load_full_block();
    let coinbase_inclusion_proof = Some(TxidInclusionProof::generate(&block.txdata, 0));
    AsmStepInput::new(block, AuxData::default(), coinbase_inclusion_proof)
}

/// Builds an [`L1Anchor`] whose tip is the parent of `block`.
pub fn create_l1_anchor_to_process_block(block: &Block) -> L1Anchor {
    let genesis_block_hash = block.header.prev_blockhash;
    let genesis_block_height = block.bip34_block_height().expect("bip34 height") - 1;
    let genesis_block = L1BlockCommitment::new(
        genesis_block_height as u32,
        genesis_block_hash.to_l1_block_id(),
    );

    L1Anchor {
        block: genesis_block,
        next_target: block.header.bits.to_consensus(),
        epoch_start_timestamp: 0,
        network: bitcoin::Network::Bitcoin,
    }
}

/// Creates the anchor pre-state corresponding to the parent of `block`.
pub fn create_genesis_anchor_state(block: &Block) -> AnchorState {
    let mut params: AsmParams = ArbitraryGenerator::new().generate();
    let anchor = create_l1_anchor_to_process_block(block);
    params.anchor = anchor;
    construct_genesis_state(&params)
}

/// Creates an ASM spec.
pub fn create_asm_spec() -> StrataAsmSpec {
    StrataAsmSpec
}

/// Creates the Moho pre-state from an existing [`AnchorState`].
pub fn create_moho_prestate(anchor_state: &AnchorState) -> MohoState {
    let inner_state = AsmStfProgram::compute_state_commitment(anchor_state)
        .into_inner()
        .into();

    MohoState {
        inner_state,
        next_predicate: PredicateKey::always_accept(),
        export_state: ExportState::new(vec![]),
    }
}

/// Creates a runtime input for a single ASM STF step.
pub fn create_runtime_input(step_input: &AsmStepInput) -> RuntimeInput {
    let inner_pre_state = create_genesis_anchor_state(step_input.block());
    let moho_pre_state = create_moho_prestate(&inner_pre_state);
    RuntimeInput::new(
        moho_pre_state,
        inner_pre_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    )
}

/// Creates a matching `(RuntimeInput, StrataAsmSpec)` test pair.
pub fn create_runtime_input_and_spec() -> (RuntimeInput, StrataAsmSpec) {
    let step_input = create_asm_step_input();
    let spec = create_asm_spec();
    let runtime_input = create_runtime_input(&step_input);
    (runtime_input, spec)
}
