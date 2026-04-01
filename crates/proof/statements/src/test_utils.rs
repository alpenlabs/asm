//! Test utility constructors for ASM STF proof inputs/specs.
//!
//! This module is intended for integration binaries/tests that need a known-good
//! `RuntimeInput`/`StrataAsmSpec` pair for exercising the proof program.

use bitcoin::Block;
use moho_runtime_impl::RuntimeInput;
use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState};
use ssz::Encode;
use strata_asm_common::{
    AnchorState, AsmHistoryAccumulatorState, AuxData, ChainViewState, HeaderVerificationState,
};
use strata_asm_spec::StrataAsmSpec;
use strata_btc_types::{BlockHashExt, GenesisL1View};
use strata_btc_verification::TxidInclusionProof;
use strata_identifiers::L1BlockCommitment;
use strata_l1_txfmt::MagicBytes;
use strata_predicate::PredicateKey;
use strata_test_utils_btc::BtcMainnetSegment;

use crate::moho_program::{input::AsmStepInput, program::AsmStfProgram};

/// Creates a single-step input from a fixed test Bitcoin block.
pub fn create_asm_step_input() -> AsmStepInput {
    let block = BtcMainnetSegment::load_full_block();
    let coinbase_inclusion_proof = Some(TxidInclusionProof::generate(&block.txdata, 0));
    AsmStepInput::new(block, AuxData::default(), coinbase_inclusion_proof)
}

/// Builds a genesis L1 view whose tip is the parent of `block`.
pub fn create_genesis_l1_view_to_process_block(block: &Block) -> GenesisL1View {
    let genesis_block_hash = block.header.prev_blockhash;
    let genesis_block_height = block.bip34_block_height().expect("bip34 height") - 1;
    let genesis_block = L1BlockCommitment::new(
        genesis_block_height as u32,
        genesis_block_hash.to_l1_block_id(),
    );

    GenesisL1View {
        blk: genesis_block,
        next_target: block.header.bits.to_consensus(),
        epoch_start_timestamp: 0,
        last_11_timestamps: [0u32; 11],
    }
}

/// Creates the anchor pre-state corresponding to the parent of `block`.
pub fn create_genesis_anchor_state(block: &Block) -> AnchorState {
    let genesis_view = create_genesis_l1_view_to_process_block(block);
    let pow_state = HeaderVerificationState::new(bitcoin::Network::Signet, &genesis_view);
    let chain_view = ChainViewState {
        pow_state,
        history_accumulator: AsmHistoryAccumulatorState::new(genesis_view.blk.height() as u64),
    };

    AnchorState {
        magic: AnchorState::magic_ssz(MagicBytes::new(*b"ALPN")),
        chain_view,
        sections: Vec::new().into(),
    }
}

/// Creates an ASM spec.
pub fn create_asm_spec() -> StrataAsmSpec {
    StrataAsmSpec
}

/// Creates the Moho pre-state matching `create_genesis_anchor_state`.
pub fn create_moho_prestate(block: &Block) -> MohoState {
    let anchor_state = create_genesis_anchor_state(block);
    let inner_state = AsmStfProgram::compute_state_commitment(&anchor_state)
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
    let moho_pre_state = create_moho_prestate(step_input.block());
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
