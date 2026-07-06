//! ASM guest simulating the artifact from before the unstake fork existed.
//!
//! Identical to `guest-asm` except for the baked schedule: the unstake fork
//! never activates. Upgrade tests use its VK as the genesis ASM predicate and
//! then upgrade to the production guest, exercising the fork boundary without
//! maintaining an actual historical ELF.
#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use strata_asm_proof_impl::{statements::process_asm_stf, ForkSchedule, StfParams};
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

fn main() {
    // Hardcoded on purpose: the verifying key must commit to the STF params.
    // This artifact predates every fork, so nothing ever activates.
    process_asm_stf(
        &Sp1ZkVmEnv,
        StfParams {
            forks: ForkSchedule::all_disabled(),
        },
    )
}
