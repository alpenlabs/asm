#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use moho_recursive_proof::process_recursive_moho_proof;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

fn main() {
    process_recursive_moho_proof(&Sp1ZkVmEnv)
}
