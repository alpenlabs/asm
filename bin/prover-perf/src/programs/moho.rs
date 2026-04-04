use std::{fs, sync::LazyLock};

use moho_recursive_proof::{
    test_utils::{create_input, SchnorrPredicate},
    MohoRecursiveProgram,
};
use sp1_sdk::HashableKey;
use strata_asm_sp1_guest_builder::MOHO_ELF_PATH;
use strata_predicate::PredicateKey;
use zkaleido::{PerformanceReport, ZkVmProgramPerf};
use zkaleido_sp1_host::SP1Host;

use crate::programs::compute_sp1_predicate_key;

static MOHO_HOST: LazyLock<SP1Host> = LazyLock::new(|| {
    let elf = fs::read(MOHO_ELF_PATH)
        .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"));
    SP1Host::init(&elf)
});

pub(crate) fn gen_perf_report() -> PerformanceReport {
    // TODO(STR-2797): Use Groth16Predicate instead of SchnorrPredicate
    let moho = SchnorrPredicate::new_random();
    let step = SchnorrPredicate::new_random();
    let input = create_input(1, 2, None, &moho, &step);

    MohoRecursiveProgram::perf_report(&input, &*MOHO_HOST)
        .expect("failed to generate performance report")
}

pub(crate) fn moho_predicate_key() -> PredicateKey {
    let vk = MOHO_HOST.proving_key.vk.bytes32_raw();
    compute_sp1_predicate_key(vk)
}
