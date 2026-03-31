//! Build script for SP1 guest artifacts (`guest-asm`, `guest-moho`) used by ASM
//! proof workflows.
//!
//! # Environment variables
//!
//! - **`ASM_PARAMS_JSON`** — when set and non-empty, the value is forwarded to guest builds so that
//!   `strata-asm-spec` can embed the params at compile time on `target_os = "zkvm"`. When missing
//!   or empty, `SP1_SKIP_PROGRAM_BUILD` is set to `true`, causing `sp1-build` to skip expensive
//!   guest compilation while still exporting `SP1_ELF_*` path env vars for downstream crates.
//!
//! Both variables are registered with `cargo:rerun-if-env-changed` so the build
//! script re-runs whenever either value changes.
//!
//! # Features
//!
//! - **`docker-build`** — when enabled, guest programs are compiled inside Docker via
//!   `build_program_with_args` instead of locally. This only affects builds where compilation is
//!   not skipped.

use std::env;

#[cfg(not(feature = "docker-build"))]
use sp1_build::build_program;
#[cfg(feature = "docker-build")]
use sp1_build::{build_program_with_args, BuildArgs};

const ASM_PARAMS_ENV: &str = "ASM_PARAMS_JSON";
const SP1_SKIP_BUILD_ENV: &str = "SP1_SKIP_PROGRAM_BUILD";

fn main() {
    println!("cargo:rerun-if-env-changed={ASM_PARAMS_ENV}");
    println!("cargo:rerun-if-env-changed={SP1_SKIP_BUILD_ENV}");

    if let Some(asm_params_json) = read_asm_params_json() {
        // Propagate to nested guest builds so strata-asm-spec can embed params on zkvm target.
        env::set_var(ASM_PARAMS_ENV, asm_params_json);
    } else {
        println!("cargo:warning={ASM_PARAMS_ENV} is not set; skipping SP1 guest compilation.");
        env::set_var(SP1_SKIP_BUILD_ENV, "true");
    }

    #[cfg(feature = "docker-build")]
    {
        let build_args = BuildArgs {
            docker: true,
            workspace_directory: Some("../../".to_owned()),
            ..BuildArgs::default()
        };

        build_program_with_args("guest-asm", build_args.clone());
        build_program_with_args("guest-moho", build_args);
    }

    #[cfg(not(feature = "docker-build"))]
    {
        build_program("guest-asm");
        build_program("guest-moho");
    }
}

fn read_asm_params_json() -> Option<String> {
    env::var(ASM_PARAMS_ENV)
        .map(|value| value.trim().to_owned())
        .ok()
        .filter(|value| !value.is_empty())
}
