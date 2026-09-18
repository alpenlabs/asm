use std::{env::var, path::Path};

use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    let out_dir = var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated.rs");

    build_ssz_files(
        &["threshold.ssz"],
        "ssz",
        &[],
        output_path.to_str().expect("output path is valid"),
        ModuleGeneration::NestedModules,
    )
    .expect("Failed to generate SSZ types");

    println!("cargo:rerun-if-changed=ssz/threshold.ssz");
}
