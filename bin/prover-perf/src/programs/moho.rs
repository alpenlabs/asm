use std::{fs, path::Path};

use moho_recursive_proof::{
    test_utils::create_predicate_inclusion_proof, MohoRecursiveInput, MohoRecursiveProgram,
};
use moho_types::{
    ExportState, InnerStateCommitment, MohoState, StepMohoAttestation, StepMohoProof,
};
use ssz::Decode;
use strata_asm_sp1_guest_builder::MOHO_ELF_PATH;
use strata_predicate::PredicateKey;
use zkaleido::{ExecutionSummary, ProofReceiptWithMetadata, ZkVmExecutor, ZkVmProgram};
use zkaleido_sp1_host::SP1Host;

use crate::programs::{compute_sp1_predicate_key, INITIAL_ASM_STATE_ROOT_FILE};

pub(crate) async fn gen_execution_summary() -> ExecutionSummary {
    let host = init_moho_host().await;
    let input = create_moho_recursive_input(compute_sp1_predicate_key(host.program_id().0));
    <MohoRecursiveProgram as ZkVmProgram>::execute(&input, &host)
        .expect("failed to generate execution summary")
}

pub(crate) async fn gen_proof() -> ProofReceiptWithMetadata {
    let host = init_moho_host().await;
    let input = create_moho_recursive_input(compute_sp1_predicate_key(host.program_id().0));
    MohoRecursiveProgram::prove(&input, &host).expect("failed to generate Moho recursive proof")
}

async fn init_moho_host() -> SP1Host {
    let elf = fs::read(MOHO_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"));
    SP1Host::init(&elf).await
}

fn create_moho_recursive_input(moho_predicate: PredicateKey) -> MohoRecursiveInput {
    let (asm_predicate, incremental_step_proof) = load_asm_stf_predicate_and_proof();

    let moho_pre_state = MohoState::new(
        InnerStateCommitment::from(load_initial_asm_state_root()),
        asm_predicate.clone(),
        ExportState::new(vec![]).expect("empty export state is valid"),
    );
    let step_predicate_merkle_proof = create_predicate_inclusion_proof(&moho_pre_state);

    MohoRecursiveInput::new(
        moho_predicate,
        None,
        incremental_step_proof,
        asm_predicate,
        step_predicate_merkle_proof,
    )
}

fn load_asm_stf_predicate_and_proof() -> (PredicateKey, StepMohoProof) {
    let proof_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("asm-stf_SP1_v6.1.0.proof");
    let asm_stf_proof = ProofReceiptWithMetadata::load(proof_path).expect("failed to open proof");
    let asm_predicate = compute_sp1_predicate_key(asm_stf_proof.metadata().program_id().0);
    let proven_moho_attestation =
        StepMohoAttestation::from_ssz_bytes(asm_stf_proof.receipt().public_values().as_bytes())
            .expect("invalid SSZ for ASM STF proof public values");
    let incremental_step_proof = StepMohoProof::new(
        proven_moho_attestation,
        asm_stf_proof.receipt().proof().as_bytes().to_vec(),
    );

    (asm_predicate, incremental_step_proof)
}

/// Loads the moho pre-state's inner-state commitment (the ASM state root) from the on-disk
/// artifact persisted alongside the hardcoded ASM STF proof. Kept on disk so it refreshes
/// atomically with the proof during `--generate-proof`, instead of needing a manual constant
/// update after every breaking ASM state change.
fn load_initial_asm_state_root() -> [u8; 32] {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(INITIAL_ASM_STATE_ROOT_FILE);
    let bytes =
        fs::read(&path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        panic!(
            "expected 32 bytes in {}, got {}",
            path.display(),
            bytes.len()
        )
    })
}
