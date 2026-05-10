//! Checkpoint verification logic for ASM.
//!
//! Owns the checkpoint subprotocol's verified-tip + funds state, the validation function
//! that authenticates a checkpoint envelope and extracts withdrawal intents, and the
//! associated error types. Reusable independently of the subprotocol trait wiring.

mod deposit_pool;
mod errors;
mod state;
mod verification;

pub use errors::CheckpointValidationError;
pub use state::CheckpointState;
pub use verification::{CheckpointL1Range, verify_progression, verify_sequencer_predicate};
