//! Build script for SP1 guest artifacts (`guest-asm`, `guest-moho`) used by ASM proof workflows.
//!
//! Compiled ELFs are emitted to `<crate>/elfs/{asm,moho}.elf` regardless of the `docker-build`
//! feature, so consumers can reference a stable path that survives `cargo clean`.
//!
//! # Features
//!
//! - **`docker-build`** — when enabled, guest programs are compiled inside Docker via
//!   `build_program_with_args` instead of locally. The output location is unchanged.

use sp1_build::{build_program_with_args, BuildArgs};

const ELFS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs");

fn main() {
    println!("cargo:rerun-if-env-changed=SP1_SKIP_PROGRAM_BUILD");
    println!("cargo:warning=exporting SP1 guest ELFs to {ELFS_DIR}");

    let base = BuildArgs {
        output_directory: Some(ELFS_DIR.to_owned()),
        #[cfg(feature = "docker-build")]
        docker: true,
        #[cfg(feature = "docker-build")]
        workspace_directory: Some("../../".to_owned()),
        ..BuildArgs::default()
    };

    build_program_with_args(
        "guest-asm",
        BuildArgs {
            elf_name: Some("asm.elf".to_owned()),
            ..base.clone()
        },
    );
    build_program_with_args(
        "guest-moho",
        BuildArgs {
            elf_name: Some("moho.elf".to_owned()),
            ..base
        },
    );
}
