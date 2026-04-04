#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use strata_asm_proof_impl::statements::process_asm_stf;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

fn main() {
    process_asm_stf(&Sp1ZkVmEnv)
}
