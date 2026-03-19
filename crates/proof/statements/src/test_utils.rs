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
use strata_asm_params::{AsmParams, SubprotocolInstance};
use strata_asm_spec::StrataAsmSpec;
use strata_btc_types::{BlockHashExt, GenesisL1View};
use strata_identifiers::L1BlockCommitment;
use strata_l1_txfmt::MagicBytes;
use strata_predicate::PredicateKey;
use strata_test_utils_btc::segment::BtcChainSegment;

use crate::moho_program::{
    input::{AsmStepInput, L1Block},
    program::AsmStfProgram,
};

const SUBPROTOCOLS_JSON: &str = r#"[
    {"Admin":{"strata_administrator":{"keys":["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],"threshold":1},"strata_sequencer_manager":{"keys":["03cf59a1a5ef092ced386f2651b610d3dd2cc6806bb74a8eab95c1f3b2f3d81772","02343edde4a056e00af99aa49de60df03859d1b79ebbc4f3f6da8fbd0053565de3"],"threshold":1},"confirmation_depth":144,"max_seqno_gap":10}},
    {"Checkpoint":{"sequencer_predicate":"Sp1Groth16","checkpoint_predicate":"AlwaysAccept","genesis_l1_height":3334849731,"genesis_ol_blkid":"c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"}},
    {"Bridge":{"operators":["02becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70"],"denomination":0,"assignment_duration":0,"operator_fee":0,"recovery_delay":0}}
]"#;

/// Creates a single-step input from a fixed test Bitcoin block.
pub fn create_asm_step_input() -> AsmStepInput {
    let block = BtcChainSegment::load_full_block();
    AsmStepInput::new(L1Block(block), AuxData::default())
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
        chain_view,
        sections: Vec::new().into(),
    }
}

/// Creates an ASM spec with fixed subprotocol params and provided L1 view.
pub fn create_asm_spec(genesis_view: GenesisL1View) -> StrataAsmSpec {
    let subprotocols: Vec<SubprotocolInstance> =
        serde_json::from_str(SUBPROTOCOLS_JSON).expect("deserialize subprotocols");
    let params = AsmParams {
        magic: MagicBytes::new(*b"ALPN"),
        l1_view: genesis_view,
        subprotocols,
    };
    StrataAsmSpec::from_asm_params(&params)
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
    let block = step_input.block();
    let inner_pre_state = create_genesis_anchor_state(&block.0);
    let moho_pre_state = create_moho_prestate(&block.0);
    RuntimeInput::new(
        moho_pre_state,
        inner_pre_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    )
}

/// Creates a matching `(RuntimeInput, StrataAsmSpec)` test pair.
pub fn create_runtime_input_and_spec() -> (RuntimeInput, StrataAsmSpec) {
    let step_input = create_asm_step_input();
    let block = step_input.block();
    let l1view = create_genesis_l1_view_to_process_block(&block.0);
    let spec = create_asm_spec(l1view);
    let runtime_input = create_runtime_input(&step_input);
    (runtime_input, spec)
}
