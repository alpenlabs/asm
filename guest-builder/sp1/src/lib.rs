//! Public ELF path exports for the SP1 guests.
//!
//! The ASM ELF is emitted into `<crate>/generated/` by `build.rs`. The Moho ELF is fetched into
//! the same directory from a moho release by `contrib/fetch_moho_artifacts.sh`. The constants
//! below point at those stable paths rather than into cargo's `target/`.

pub const ASM_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/generated/asm.elf");
pub const MOHO_ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/generated/moho.elf");
