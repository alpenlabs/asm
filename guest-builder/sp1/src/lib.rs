//! Public ELF path exports produced by this crate's build script.
//!
//! ELFs are emitted into `<crate>/elfs/` (see `build.rs`); the constants
//! below point at those stable paths rather than into cargo's `target/`.

pub const ASM_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/asm.elf");
pub const MOHO_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/moho.elf");
