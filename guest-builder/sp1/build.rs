//! Build script for SP1 guest artifacts (`guest-asm`, `guest-moho`) used by ASM proof workflows.
//!
//! # Features
//!
//! - **`docker-build`** — when enabled, guest programs are compiled inside Docker via
//!   `build_program_with_args` instead of locally.

use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    println!("cargo:rerun-if-env-changed=SP1_SKIP_PROGRAM_BUILD");

    #[cfg(not(feature = "docker-build"))]
    let build_args = BuildArgs::default();

    #[cfg(feature = "docker-build")]
    let build_args = BuildArgs {
        docker: true,
        workspace_directory: Some("../../".to_owned()),
        ..BuildArgs::default()
    };

    build_program_with_args("guest-asm", build_args.clone());
    build_program_with_args("guest-moho", build_args);
}
