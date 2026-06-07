//! Lightweight sled-backed storage for the ASM runner.
//!
//! Replaces alpen's `strata-state`, `strata-storage`, and `strata-db-store-sled`
//! with a self-contained implementation that has zero alpen dependencies.
//!
//! Each store is split into an async persistence trait and a sled-backed
//! implementation (in the private `sled` module) that also exposes synchronous
//! inherent methods for the sync worker thread:
//! - [`AsmStateDb`] / [`SledAsmStateDb`] — anchor states, keyed by block commitment
//! - [`AsmAuxDataDb`] / [`SledAsmAuxDataDb`] — auxiliary data, keyed by block commitment
//! - [`AsmManifestDb`] / [`SledAsmManifestDb`] — full manifests, keyed by block commitment
//! - [`AsmManifestMmrDb`] / [`SledAsmManifestMmrDb`] — manifest hash MMR, keyed by L1 height
//!
//! The commitment-keyed stores ([`AsmStateDb`], [`AsmAuxDataDb`],
//! [`AsmManifestDb`]) key each entry by its [`L1BlockCommitment`] — height plus
//! block hash — so `put` overwrites only when the *same* block is written again
//! (e.g. a restart or reorg replay re-processes it). A block's derived state,
//! aux data, and manifest are deterministic, so such a rewrite stores the same
//! value; we never expect to overwrite a key with a different value. (The MMR is
//! keyed by L1 height instead, and *does* replace a leaf with a different value
//! when a reorg swaps the block at that height.)
//!
//! Per-container export entries moved to `strata-asm-moho-storage`, persisted
//! by the Moho worker alongside the `MohoState` whose `ExportState` MMR they
//! mirror.
//!
//! [`L1BlockCommitment`]: strata_identifiers::L1BlockCommitment

mod aux;
mod manifest;
mod manifest_mmr;
mod sled;
mod state;

pub use aux::AsmAuxDataDb;
pub use manifest::AsmManifestDb;
pub use manifest_mmr::AsmManifestMmrDb;
pub use sled::{SledAsmAuxDataDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb};
pub use state::AsmStateDb;
