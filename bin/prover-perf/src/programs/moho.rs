use std::{fs, path::Path};

use moho_recursive_proof::{
    test_utils::create_predicate_inclusion_proof, MohoRecursiveInput, MohoRecursiveProgram,
};
use moho_runtime_interface::MohoProgram;
use moho_types::{StateRefAttestation, StepMohoAttestation, StepMohoProof};
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
use zkaleido::{ExecutionSummary, ProofReceiptWithMetadata, ZkVmExecutor, ZkVmProgram};
use zkaleido_sp1_groth16_verifier::VK_HASH_PREFIX_LENGTH;
use zkaleido_sp1_host::SP1Host;

use crate::programs::compute_sp1_predicate_key;

async fn init_moho_host() -> SP1Host {
    let elf = fs::read(MOHO_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"));
    SP1Host::init(&elf).await
}

pub(crate) async fn gen_execution_summary() -> ExecutionSummary {
    let host = init_moho_host().await;
    let input = create_moho_recursive_input(&host);
    <MohoRecursiveProgram as ZkVmProgram>::execute(&input, &host)
        .expect("failed to generate execution summary")
}

pub(crate) async fn gen_proof() -> ProofReceiptWithMetadata {
    let host = init_moho_host().await;
    let input = create_moho_recursive_input(&host);
    MohoRecursiveProgram::prove(&input, &host).expect("failed to generate performance report")
}

fn compute_moho_predicate_key(host: &SP1Host) -> PredicateKey {
    compute_sp1_predicate_key(host.program_id().0)
}

fn load_asm_stf_predicate_and_proof() -> (PredicateKey, StepMohoProof) {
    let proof_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asm-stf_SP1_v6.1.0.proof.bin");
    let asm_stf_proof = ProofReceiptWithMetadata::load(proof_path).expect("failed to open proof");

    let asm_predicate = compute_sp1_predicate_key(asm_stf_proof.metadata().program_id().0);

    let proven_moho_attestation =
        StepMohoAttestation::from_ssz_bytes(asm_stf_proof.receipt().public_values().as_bytes())
            .unwrap();

    let proof = &asm_stf_proof.receipt().proof().as_bytes()[VK_HASH_PREFIX_LENGTH..];
    let incremental_step_proof = StepMohoProof::new(proven_moho_attestation, proof.to_vec());

    (asm_predicate, incremental_step_proof)
}

fn create_moho_recursive_input(host: &SP1Host) -> MohoRecursiveInput {
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
        compute_moho_predicate_key(host),
        None,
        incremental_step_proof,
        asm_predicate,
        step_predicate_merkle_proof,
    )
}
