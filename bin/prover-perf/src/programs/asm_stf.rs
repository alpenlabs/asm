use std::fs;

use strata_asm_proof_impl::{program::AsmStfProofProgram, test_utils::create_runtime_input};
use strata_asm_sp1_guest_builder::ASM_ELF_PATH;
use zkaleido::{PerformanceReport, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

pub(crate) fn gen_perf_report() -> PerformanceReport {
    let input = create_runtime_input();
    let elf = fs::read(ASM_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_ELF_PATH}: {err}"));
    let host = SP1Host::init(&elf);
    AsmStfProofProgram::perf_report(&input, &host).expect("failed to generate performance report")
}
