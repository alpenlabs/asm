//! Checkpoint verification logic for ASM.
//!
//! Owns the checkpoint subprotocol's verified-tip + funds state, the validation function
//! that authenticates a checkpoint envelope and extracts withdrawal intents, and the
//! associated error types. Reusable independently of the subprotocol trait wiring.

pub mod errors;
pub mod state;
pub mod verification;
