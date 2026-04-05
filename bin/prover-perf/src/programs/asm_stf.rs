use std::{fs, sync::LazyLock};

use moho_runtime_impl::RuntimeInput;
use moho_types::MohoAttestation;
use sp1_sdk::HashableKey;
use ssz::{Decode, Encode};
use strata_asm_proof_impl::{
    program::AsmStfProofProgram,
    test_utils::{
        create_asm_step_input, create_deterministic_genesis_anchor_state, create_moho_state,
    },
};
use strata_asm_sp1_guest_builder::ASM_ELF_PATH;
use strata_predicate::PredicateKey;
use zkaleido::{PerformanceReport, ProofReceiptWithMetadata, ZkVmProgram, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

use crate::programs::compute_sp1_predicate_key;

static ASM_HOST: LazyLock<SP1Host> = LazyLock::new(|| {
    let elf = fs::read(ASM_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_ELF_PATH}: {err}"));
    SP1Host::init(&elf)
});

/// Creates a runtime input for a single ASM STF step.
pub(crate) fn create_runtime_input() -> RuntimeInput {
    let step_input = create_asm_step_input();
    let inner_pre_state = create_deterministic_genesis_anchor_state(step_input.block());
    let moho_pre_state = create_moho_state(&inner_pre_state, asm_predicate_key());
    RuntimeInput::new(
        moho_pre_state,
        inner_pre_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    )
}

pub(crate) fn check_proof_and_execution() {
    let input = create_runtime_input();
    let executed_moho_transition = AsmStfProofProgram::execute(&input).unwrap();

    let asm_stf_proof = ProofReceiptWithMetadata::load("asm-stf_SP1_v5.0.0.proof.bin")
        .expect("failed to open proof");
    let proven_moho_transition =
        MohoAttestation::from_ssz_bytes(asm_stf_proof.receipt().public_values().as_bytes())
            .unwrap();

    assert_eq!(executed_moho_transition, proven_moho_transition);
}

pub(crate) fn gen_perf_report() -> PerformanceReport {
    check_proof_and_execution();
    let input = create_runtime_input();
    AsmStfProofProgram::perf_report(&input, &*ASM_HOST)
        .expect("failed to generate performance report")
}

pub(crate) fn gen_proof() -> ProofReceiptWithMetadata {
    let input = create_runtime_input();
    AsmStfProofProgram::prove(&input, &*ASM_HOST).expect("failed to generate proof")
}

pub(crate) fn asm_predicate_key() -> PredicateKey {
    let vk = ASM_HOST.proving_key.vk.bytes32_raw();
    compute_sp1_predicate_key(vk)
}
