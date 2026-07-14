//! Build script for generating SSZ code from schema definitions.

use std::{env, fs, path::Path};

#[cfg(feature = "ssz")]
use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated.rs");

    // Only generate SSZ types when the ssz feature is enabled.
    if env::var("CARGO_FEATURE_SSZ").is_ok() {
        #[cfg(feature = "ssz")]
        {
            let entry_points = ["header_verification.ssz"];
            let base_dir = "ssz";
            let crates = ["strata_identifiers"];

            build_ssz_files(
                &entry_points,
                base_dir,
                &crates,
                output_path.to_str().expect("output path is valid UTF-8"),
                ModuleGeneration::NestedModules,
            )
            .expect("Failed to generate SSZ types");

            println!("cargo:rerun-if-changed=ssz/header_verification.ssz");
        }
    } else {
        fs::write(&output_path, "// SSZ feature not enabled\n")
            .expect("Failed to write placeholder file");
    }
}
