use std::{env::var, path::Path};

use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    let out_dir = var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated.rs");

    let entry_points = ["state.ssz"];
    let base_dir = "ssz";
    let crates = [
        "strata_predicate",
        "strata_btc_types",
        "strata_asm_proto_checkpoint_types",
    ];

    build_ssz_files(
        &entry_points,
        base_dir,
        &crates,
        output_path.to_str().expect("output path is valid"),
        ModuleGeneration::NestedModules,
    )
    .expect("Failed to generate SSZ types");

    println!("cargo:rerun-if-changed=ssz/state.ssz");
}
