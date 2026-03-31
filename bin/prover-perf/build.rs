use std::{env, fs};

use sp1_build::build_program;

fn main() {
    let asm_params = fs::read_to_string("asm-params.json").expect("failed to read asm-params.json");

    // Set env var so it propagates to the guest build via sp1_build::build_program.
    // The spec crate's build.rs validates this, and env!("ASM_PARAMS_JSON") embeds it.
    env::set_var("ASM_PARAMS_JSON", asm_params.trim());
    println!("cargo:rerun-if-changed=asm-params.json");

    build_program("../../guest-builder/sp1/guest-asm");
    build_program("../../guest-builder/sp1/guest-moho");
}
