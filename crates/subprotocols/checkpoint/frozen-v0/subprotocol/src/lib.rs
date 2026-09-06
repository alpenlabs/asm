//! Checkpoint subprotocol as released in `v0.3.0-rc.2`.
//!
//! FROZEN. Every file taken verbatim from tag `v0.3.0-rc.2` (commit 45a1fa2) at
//! `crates/subprotocols/checkpoint/subprotocol/`, adjusted only where the
//! current dependencies force it; each adjustment is marked `DEVIATION`.
//!
//! What changed after these rules (`7e0b873`): the released implementation
//! applied `UpdateCheckpointPredicate` immediately, whereas the current one
//! queues a range-keyed pending transition, selects active-versus-pending by the
//! checkpoint's covered range, and notifies administration on promotion. See
//! `strata-asm-proto-checkpoint` for the current behaviour.
//!
//! Released documentation follows.

//! Checkpoint subprotocol for ASM.
//!
//! Wires the pure verification logic from [`strata_checkpoint_verification_v0`] into the
//! [`strata_asm_common::Subprotocol`] trait — handling checkpoint transactions, dispatching
//! incoming messages from the admin and bridge subprotocols, and emitting tip-update logs.

mod handler;
mod subprotocol;

pub use strata_checkpoint_verification_v0::CheckpointState;
pub use subprotocol::CheckpointSubprotocolV0;
