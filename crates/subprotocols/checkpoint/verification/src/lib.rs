//! Checkpoint verification logic for ASM.
//!
//! Owns the checkpoint subprotocol's verified-tip + funds state, the validation function
//! that authenticates a checkpoint envelope and extracts withdrawal intents, and the
//! associated error types. Reusable independently of the subprotocol trait wiring.

mod deposit_pool;
mod errors;
mod state;
mod verification;

#[allow(
    clippy::all,
    unreachable_pub,
    clippy::allow_attributes,
    clippy::absolute_paths,
    reason = "generated code"
)]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

// Admin sizes its post-enactment occupancy accounting from the hand-written constant while the
// transition list's real capacity comes from the schema constant in `ssz/state.ssz`. A larger
// Rust value would turn checkpoint's capacity check into a consensus-halting panic, so the two
// must agree.
const _: () = assert!(
    ssz_generated::ssz::state::MAX_PENDING_PREDICATE_TRANSITIONS as usize
        == strata_asm_checkpoint_types::MAX_PENDING_PREDICATE_TRANSITIONS
);

pub use errors::CheckpointValidationError;
pub use ssz_generated::ssz::state::CheckpointState;
pub(crate) use ssz_generated::ssz::state::DepositPool;
pub use state::PredicateSelection;
pub use verification::{CheckpointL1Range, verify_progression, verify_sequencer_predicate};
