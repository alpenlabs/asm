//! Checkpoint subprotocol for ASM.
//!
//! Wires the pure verification logic from [`strata_checkpoint_verification`] into the
//! [`strata_asm_common::Subprotocol`] trait — handling checkpoint transactions, dispatching
//! incoming messages from the admin and bridge subprotocols, and emitting tip-update logs.

pub mod handler;
pub mod subprotocol;

pub use strata_checkpoint_verification::state;
