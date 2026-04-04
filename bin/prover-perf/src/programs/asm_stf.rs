use std::{fs, sync::LazyLock};

use sp1_sdk::HashableKey;
use strata_asm_proof_impl::{program::AsmStfProofProgram, test_utils::create_runtime_input};
use strata_asm_sp1_guest_builder::ASM_ELF_PATH;
use strata_predicate::PredicateKey;
use zkaleido::{PerformanceReport, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

use crate::programs::compute_sp1_predicate_key;

static ASM_HOST: LazyLock<SP1Host> = LazyLock::new(|| {
    let elf = fs::read(ASM_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_ELF_PATH}: {err}"));
    SP1Host::init(&elf)
});

pub(crate) fn gen_perf_report() -> PerformanceReport {
    let input = create_runtime_input();
    AsmStfProofProgram::perf_report(&input, &*ASM_HOST)
        .expect("failed to generate performance report")
}

pub(crate) fn asm_predicate_key() -> PredicateKey {
    let vk = ASM_HOST.proving_key.vk.bytes32_raw();
    compute_sp1_predicate_key(vk)
}
