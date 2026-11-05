//! Checkpoint subprotocol for ASM.
//!
//! Wires the pure verification logic from [`strata_checkpoint_verification`] into the
//! [`strata_asm_common::Subprotocol`] trait — handling checkpoint transactions, dispatching
//! incoming messages from the admin and bridge subprotocols, and emitting tip-update logs.

mod auth;
mod errors;
mod handler;
mod subprotocol;

#[cfg(test)]
mod test_utils;

pub use auth::{authenticate_checkpoint_tx, parse_sequencer_envelope};
pub use errors::CheckpointEnvelopeError;
pub use strata_checkpoint_verification::CheckpointState;
pub use subprotocol::CheckpointSubprotocol;
