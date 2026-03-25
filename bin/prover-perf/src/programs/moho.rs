use std::fs;

use moho_recursive_proof::{
    test_utils::{create_input, SchnorrPredicate},
    MohoRecursiveProgram,
};
use zkaleido::{PerformanceReport, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

const MOHO_ELF_PATH: &str = env!("SP1_ELF_guest-sp1-moho");

fn load_elf() -> Vec<u8> {
    fs::read(MOHO_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"))
}

pub(crate) fn gen_perf_report() -> PerformanceReport {
    let moho = SchnorrPredicate::new();
    let step = SchnorrPredicate::new();

    let input = create_input(1, 2, None, &moho, &step);
    let elf = load_elf();
    let host = SP1Host::init(&elf);
    MohoRecursiveProgram::perf_report(&input, &host).expect("failed to generate performance report")
}
