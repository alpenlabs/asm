//! Persistence layer for ASM and Moho proofs.
//!
//! This crate defines three storage traits that together cover the full
//! lifecycle of a proof — from submission to a remote prover, through status
//! tracking, to final local storage:
//!
//! - [`ProofDb`] — stores and retrieves finalised ASM step proofs and Moho recursive proofs, keyed
//!   by their L1 block range or commitment.
//! - [`RemoteProofMappingDb`] — maintains a bidirectional mapping between local
//!   [`ProofId`](strata_asm_proof_types::ProofId)s and opaque
//!   [`RemoteProofId`](strata_asm_proof_types::RemoteProofId)s assigned by the remote prover
//!   service.
//! - [`RemoteProofStatusDb`] — tracks the execution status of in-flight remote proof jobs until
//!   their results are retrieved and stored locally.
//!
//! A sled-backed implementation, [`SledProofDb`], is provided. Per-block
//! `MohoState` snapshots are persisted separately by `strata-asm-moho-storage`;
//! both can share one sled directory by opening the `sled::Db` yourself and
//! passing it to each — sled does not allow the same path to be opened twice in
//! a process.

mod proof_db;
mod remote_mapping;
mod remote_status;
mod sled;

pub use self::{
    proof_db::ProofDb,
    remote_mapping::RemoteProofMappingDb,
    remote_status::RemoteProofStatusDb,
    sled::{RemoteProofMappingError, RemoteProofStatusError, SledProofDb},
};
