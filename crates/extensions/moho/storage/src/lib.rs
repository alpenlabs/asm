//! Persistence layer for the Moho worker.
//!
//! The Moho worker derives a [`moho_types::MohoState`] for each L1 block it
//! processes and persists it here, keyed by the block's
//! [`L1BlockCommitment`](strata_identifiers::L1BlockCommitment). Alongside it
//! the worker mirrors the per-container export-entry leaves of the state's
//! `ExportState` MMR so the RPC can rebuild inclusion proofs on demand.
//!
//! Each store is split into a backend-agnostic trait and a sled-backed
//! implementation:
//!
//! - [`MohoStateDb`] / [`SledMohoStateDb`] — the Moho-state store, keyed by L1 block commitment.
//! - [`ExportEntriesDb`] / [`SledExportEntriesDb`] — the per-container export-entry index mirroring
//!   the `ExportState` MMR leaves.

mod export_entries;
mod moho_state;
mod sled;

pub use self::{
    export_entries::ExportEntriesDb,
    moho_state::MohoStateDb,
    sled::{SledExportEntriesDb, SledMohoStateDb},
};
