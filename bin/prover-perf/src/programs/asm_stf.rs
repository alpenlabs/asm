use std::fs;

use moho_runtime_impl::RuntimeInput;
use ssz::Encode;
use strata_asm_proof_impl::{
    program::AsmStfProofProgram,
    test_utils::{
        create_asm_step_input, create_deterministic_genesis_anchor_state, create_moho_state,
    },
};
use strata_asm_sp1_guest_builder::ASM_ELF_PATH;
use strata_predicate::PredicateKey;
use zkaleido::{ExecutionSummary, ProofReceiptWithMetadata, ZkVmExecutor, ZkVmProgram};
use zkaleido_sp1_host::SP1Host;

use crate::programs::compute_sp1_predicate_key;

async fn init_asm_host() -> SP1Host {
    let elf = fs::read(ASM_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_ELF_PATH}: {err}"));
    SP1Host::init(&elf).await
}

/// Creates a runtime input for a single ASM STF step.
fn create_runtime_input(host: &SP1Host) -> RuntimeInput {
    let step_input = create_asm_step_input();
    let inner_pre_state = create_deterministic_genesis_anchor_state(step_input.block());
    let moho_pre_state = create_moho_state(&inner_pre_state, compute_asm_predicate_key(host));
    RuntimeInput::new(
        moho_pre_state,
        inner_pre_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    )
}

pub(crate) async fn gen_execution_summary() -> ExecutionSummary {
    let host = init_asm_host().await;
    let input = create_runtime_input(&host);
    <AsmStfProofProgram as ZkVmProgram>::execute(&input, &host)
        .expect("failed to generate execution summary")
}

pub(crate) async fn gen_proof() -> ProofReceiptWithMetadata {
    let host = init_asm_host().await;
    let input = create_runtime_input(&host);
    AsmStfProofProgram::prove(&input, &host).expect("failed to generate proof")
}

fn compute_asm_predicate_key(host: &SP1Host) -> PredicateKey {
    compute_sp1_predicate_key(host.program_id().0)
}
