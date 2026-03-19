use std::fs;

use strata_asm_proof_impl::{
    program::AsmStfProofProgram, test_utils::create_runtime_input_and_spec,
};
use zkaleido::{PerformanceReport, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

const ASM_STF_ELF_PATH: &str = env!("SP1_ELF_guest-sp1-asm");

fn load_elf() -> Vec<u8> {
    fs::read(ASM_STF_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_STF_ELF_PATH}: {err}"))
}

pub(crate) fn gen_perf_report() -> PerformanceReport {
    let (input, _spec) = create_runtime_input_and_spec();
    let elf = load_elf();
    let host = SP1Host::init(&elf);
    AsmStfProofProgram::perf_report(&input, &host).expect("failed to generate performance report")
}
