use std::{fs, path::Path, sync::LazyLock};

use moho_recursive_proof::{
    test_utils::create_predicate_inclusion_proof, MohoRecursiveInput, MohoRecursiveProgram,
};
use moho_runtime_interface::MohoProgram;
use moho_types::{StateRefAttestation, StepMohoAttestation, StepMohoProof};
use sp1_sdk::HashableKey;
use ssz::Decode;
use strata_asm_proof_impl::{
    moho_program::program::AsmStfProgram,
    test_utils::{
        create_asm_step_input, create_deterministic_genesis_anchor_state, create_moho_state,
    },
};
use strata_asm_sp1_guest_builder::MOHO_ELF_PATH;
use strata_asm_spec::StrataAsmSpec;
use strata_asm_stf::compute_asm_transition;
use strata_predicate::PredicateKey;
use zkaleido::{PerformanceReport, ProofReceiptWithMetadata, ZkVmProgram, ZkVmProgramPerf};
use zkaleido_sp1_groth16_verifier::VK_HASH_PREFIX_LENGTH;
use zkaleido_sp1_host::SP1Host;

use crate::programs::compute_sp1_predicate_key;

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

pub(crate) fn gen_proof() -> (String, ProofReceiptWithMetadata) {
    let input = create_moho_recursive_input();
    let proof = MohoRecursiveProgram::prove(&input, &*MOHO_HOST)
        .expect("failed to generate performance report");
    (MOHO_HOST.proving_key.vk.bytes32(), proof)
}

pub(crate) fn compute_moho_predicate_key() -> PredicateKey {
    let vk = MOHO_HOST.proving_key.vk.bytes32_raw();
    compute_sp1_predicate_key(vk)
}

pub(crate) fn load_asm_stf_predicate_and_proof() -> (PredicateKey, StepMohoProof) {
    const ASM_PROGRAM_ID_STR: &str =
        "0010bd9131991c632d564370bcd99415a0f24b91baf35311a7051f4a897485c1";
    let asm_program_id: [u8; 32] = hex::decode(ASM_PROGRAM_ID_STR).unwrap().try_into().unwrap();
    let asm_predicate = compute_sp1_predicate_key(asm_program_id);

    let proof_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "asm-stf_0x{}_SP1_v5.0.0.proof.bin",
        ASM_PROGRAM_ID_STR
    ));
    let asm_stf_proof = ProofReceiptWithMetadata::load(proof_path).expect("failed to open proof");
    let proven_moho_attestation =
        StepMohoAttestation::from_ssz_bytes(asm_stf_proof.receipt().public_values().as_bytes())
            .unwrap();

    let proof = &asm_stf_proof.receipt().proof().as_bytes()[VK_HASH_PREFIX_LENGTH..];
    let incremental_step_proof = StepMohoProof::new(proven_moho_attestation, proof.to_vec());

    (asm_predicate, incremental_step_proof)
}

pub(crate) fn create_moho_recursive_input() -> MohoRecursiveInput {
    let input = create_asm_step_input();
    let asm_pre_state = create_deterministic_genesis_anchor_state(input.block());
    let (asm_predicate, incremental_step_proof) = load_asm_stf_predicate_and_proof();

    let moho_pre_state = create_moho_state(&asm_pre_state, asm_predicate.clone());

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

    let moho_post_state = create_moho_state(&asm_post_state, asm_predicate.clone());

    let moho_post_state_ref = StateRefAttestation::new(
        AsmStfProgram::compute_input_reference(&input),
        moho_post_state.compute_commitment(),
    );

    let expected_moho_attestation =
        StepMohoAttestation::new(moho_pre_state_ref, moho_post_state_ref);

    assert_eq!(
        &expected_moho_attestation,
        incremental_step_proof.attestation()
    );

    let step_predicate_merkle_proof = create_predicate_inclusion_proof(&moho_pre_state);

    MohoRecursiveInput::new(
        compute_moho_predicate_key(),
        None,
        incremental_step_proof,
        asm_predicate,
        step_predicate_merkle_proof,
    )
}
