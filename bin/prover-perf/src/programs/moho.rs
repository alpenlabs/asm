use std::{fs, sync::LazyLock};

use moho_recursive_proof::{
    test_utils::create_predicate_inclusion_proof, MohoRecursiveInput, MohoRecursiveProgram,
    MohoStateTransition, MohoTransitionWithProof,
};
use moho_runtime_interface::MohoProgram;
use moho_types::StateRefAttestation;
use sp1_sdk::HashableKey;
use ssz::Decode;
use strata_asm_proof_impl::{
    moho_program::program::AsmStfProgram,
    test_utils::{create_asm_step_input, create_genesis_anchor_state, create_moho_state},
};
use strata_asm_sp1_guest_builder::MOHO_ELF_PATH;
use strata_asm_spec::StrataAsmSpec;
use strata_asm_stf::compute_asm_transition;
use strata_predicate::PredicateKey;
use zkaleido::{PerformanceReport, ProofReceiptWithMetadata, ZkVmProgram, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

use crate::programs::{asm_stf::asm_predicate_key, compute_sp1_predicate_key};

static MOHO_HOST: LazyLock<SP1Host> = LazyLock::new(|| {
    let elf = fs::read(MOHO_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"));
    SP1Host::init(&elf)
});

pub(crate) fn gen_perf_report() -> PerformanceReport {
    let input = create_moho_recursive_input();
    MohoRecursiveProgram::perf_report(&input, &*MOHO_HOST)
        .expect("failed to generate performance report")
}

pub(crate) fn gen_proof() -> ProofReceiptWithMetadata {
    let input = create_moho_recursive_input();
    MohoRecursiveProgram::prove(&input, &*MOHO_HOST).expect("failed to generate performance report")
}

pub(crate) fn moho_predicate_key() -> PredicateKey {
    let vk = MOHO_HOST.proving_key.vk.bytes32_raw();
    compute_sp1_predicate_key(vk)
}

pub(crate) fn create_moho_recursive_input() -> MohoRecursiveInput {
    let input = create_asm_step_input();
    let asm_pre_state = create_genesis_anchor_state(input.block());
    let moho_pre_state = create_moho_state(&asm_pre_state, asm_predicate_key());

    let moho_pre_state_ref = StateRefAttestation::new(
        AsmStfProgram::extract_prev_reference(&input),
        moho_pre_state.compute_commitment(),
    );

    let asm_post_state = compute_asm_transition(
        &StrataAsmSpec,
        &asm_pre_state,
        input.block(),
        input.aux_data(),
        input.coinbase_inclusion_proof(),
    )
    .unwrap()
    .state;

    let moho_post_state = create_moho_state(&asm_post_state, asm_predicate_key());

    let moho_post_state_ref = StateRefAttestation::new(
        AsmStfProgram::compute_input_reference(&input),
        moho_post_state.compute_commitment(),
    );

    let expected_moho_transition =
        MohoStateTransition::new(moho_pre_state_ref, moho_post_state_ref);

    let asm_stf_proof = ProofReceiptWithMetadata::load("asm-stf_SP1_v5.0.0.proof.bin")
        .expect("failed to open proof");
    let proven_moho_transition =
        MohoStateTransition::from_ssz_bytes(asm_stf_proof.receipt().public_values().as_bytes())
            .unwrap();
    assert_eq!(expected_moho_transition, proven_moho_transition);

    let proof = asm_stf_proof.receipt().proof().as_bytes();
    let incremental_step_proof =
        MohoTransitionWithProof::new(expected_moho_transition, proof.to_vec());

    let step_predicate_merkle_proof = create_predicate_inclusion_proof(&moho_pre_state);

    MohoRecursiveInput::new(
        moho_predicate_key(),
        None,
        incremental_step_proof,
        asm_predicate_key(),
        step_predicate_merkle_proof,
    )
}
