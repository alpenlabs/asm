//! Public ELF path exports produced by this crate's build script.
//!
//! ELFs are emitted into `<crate>/elfs/` (see `build.rs`); the constants
//! below point at those stable paths rather than into cargo's `target/`.
//!
//! There is one ASM path per specification. Which one proves a given block is
//! not a build-time question: it is decided per block by the predicate the
//! parent handed over, so a proving node loads every ASM artifact it may need
//! and selects among them at proving time.

/// The ASM guest executing the released (`v0`) rules.
pub const ASM_V0_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/asm-v0.elf");
/// The ASM guest executing the current (`v1`) rules.
pub const ASM_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/asm.elf");
/// The Moho recursive guest, which is specification-independent.
pub const MOHO_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs/moho.elf");
