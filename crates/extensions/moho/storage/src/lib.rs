//! Persistence layer for Moho state snapshots.
//!
//! The Moho worker derives a [`moho_types::MohoState`] for each L1 block it
//! processes and persists it here, keyed by the block's
//! [`L1BlockCommitment`](strata_identifiers::L1BlockCommitment).
//!
//! - [`MohoStateDb`] — the storage trait, parameterised over an associated error type.
//! - [`SledMohoStateDb`] — a [sled](https://docs.rs/sled)-backed implementation.

mod moho_state;
mod sled;

pub use self::{moho_state::MohoStateDb, sled::SledMohoStateDb};
