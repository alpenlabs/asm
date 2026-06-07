//! Lightweight sled-backed storage for the ASM runner.
//!
//! Replaces alpen's `strata-state`, `strata-storage`, and `strata-db-store-sled`
//! with a self-contained implementation that has zero alpen dependencies.
//!
//! Storage backends:
//! - [`AsmStateDb`] — anchor states + aux data, keyed by L1 block commitment
//! - [`AsmManifestMmrDb`] / [`SledAsmManifestMmrDb`] — manifest hash MMR (append, prove, query),
//!   split into an async trait and a sled-backed impl
//! - [`ExportEntriesDb`] — per-container export entries, indexed for proof generation

mod export_entries;
mod manifest_mmr;
mod sled;
mod state;

pub use export_entries::ExportEntriesDb;
pub use manifest_mmr::AsmManifestMmrDb;
pub use sled::SledAsmManifestMmrDb;
pub use state::AsmStateDb;
