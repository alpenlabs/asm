use std::fs;

use moho_recursive_proof::{
    test_utils::{create_input, SchnorrPredicate},
    MohoRecursiveProgram,
};
use strata_asm_sp1_guest_builder::MOHO_ELF_PATH;
use zkaleido::{PerformanceReport, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

pub(crate) fn gen_perf_report() -> PerformanceReport {
    // TODO(STR-2797): Use Groth16Predicate instead of SchnorrPredicate
    let moho = SchnorrPredicate::new_random();
    let step = SchnorrPredicate::new_random();
    let input = create_input(1, 2, None, &moho, &step);

    let elf = fs::read(MOHO_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"));
    let host = SP1Host::init(&elf);
    MohoRecursiveProgram::perf_report(&input, &host).expect("failed to generate performance report")
}
