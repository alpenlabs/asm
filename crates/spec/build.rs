use std::env;

use strata_asm_params::AsmParams;

fn main() {
    println!("cargo::rerun-if-env-changed=ASM_PARAMS_JSON");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "zkvm" {
        return;
    }

    let json = match env::var("ASM_PARAMS_JSON") {
        Ok(v) => v,
        Err(_) => {
            panic!("ASM_PARAMS_JSON env var must be set when building for target_os = zkvm");
        }
    };

    // Validate the JSON deserializes into a valid AsmParams.
    let _: AsmParams =
        serde_json::from_str(&json).expect("ASM_PARAMS_JSON does not deserialize into AsmParams");
}
