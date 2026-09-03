#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use strata_asm_proof_impl::statements::process_asm_stf_v0;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

// The released rules, kept buildable so the blocks they governed stay provable:
// the recursive chain re-verifies every step from genesis, so history must remain
// reproducible under the specification that governed it. See
// `strata_asm_proof_impl::statements`.
fn main() {
    process_asm_stf_v0(&Sp1ZkVmEnv)
}
