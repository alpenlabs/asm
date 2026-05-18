use std::{fs, path::Path};

use moho_runtime_impl::RuntimeInput;
use moho_types::MohoState;
use ssz::Encode;
use strata_asm_proof_impl::{
    program::AsmStfProofProgram,
    test_utils::{
        create_asm_step_input, create_deterministic_genesis_anchor_state, create_moho_state,
    },
};
use strata_asm_sp1_guest_builder::ASM_ELF_PATH;
use zkaleido::{ExecutionSummary, ProofReceiptWithMetadata, ZkVmExecutor, ZkVmProgram};
use zkaleido_sp1_host::SP1Host;

use crate::programs::{compute_sp1_predicate_key, INITIAL_ASM_STATE_ROOT_FILE};

pub(crate) async fn gen_execution_summary() -> ExecutionSummary {
    let host = init_asm_host().await;
    let (input, _) = create_runtime_input(&host);
    <AsmStfProofProgram as ZkVmProgram>::execute(&input, &host)
        .expect("failed to generate execution summary")
}

pub(crate) async fn gen_proof() -> ProofReceiptWithMetadata {
    let host = init_asm_host().await;
    let (input, moho_pre_state) = create_runtime_input(&host);
    let proof = AsmStfProofProgram::prove(&input, &host).expect("failed to generate proof");
    save_initial_asm_state_root(&moho_pre_state);
    proof
}

async fn init_asm_host() -> SP1Host {
    let elf = fs::read(ASM_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_ELF_PATH}: {err}"));
    SP1Host::init(&elf).await
}

/// Returns the runtime input for a single ASM STF step together with the moho pre-state it
/// transitions from. The pre-state is returned so `gen_proof` can persist its inner-state
/// commitment alongside the proof.
fn create_runtime_input(host: &SP1Host) -> (RuntimeInput, MohoState) {
    let step_input = create_asm_step_input();
    let inner_pre_state = create_deterministic_genesis_anchor_state(step_input.block());
    let moho_pre_state = create_moho_state(
        &inner_pre_state,
        compute_sp1_predicate_key(host.program_id().0),
    );
    let runtime_input = RuntimeInput::new(
        moho_pre_state.clone(),
        inner_pre_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    );
    (runtime_input, moho_pre_state)
}

/// Writes the moho pre-state's inner-state commitment so the moho recursive eval can rebuild a
/// matching `MohoState` without re-deriving an `AnchorState`. Called only after the SP1 proof
/// succeeds to keep this file and `asm-stf_SP1_v6.1.0.proof.bin` updated atomically.
fn save_initial_asm_state_root(moho_pre_state: &MohoState) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(INITIAL_ASM_STATE_ROOT_FILE);
    fs::write(&path, moho_pre_state.inner_state().as_bytes())
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}
