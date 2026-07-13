#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use strata_asm_proof_impl::{statements::process_asm_stf, AsmStfParams};
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

fn main() {
    // Hardcoded on purpose: the verifying key must commit to the STF params.
    process_asm_stf(&Sp1ZkVmEnv, AsmStfParams::default())
}
