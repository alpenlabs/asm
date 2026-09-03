//! Checkpoint verification as released in `v0.3.0-rc.2`.
//!
//! FROZEN. This crate reproduces the released `strata-checkpoint-verification`
//! whole — state layout, verified-tip and funds logic, envelope validation, and
//! error types — so that the released rules can still be executed for the
//! blocks they governed.
//!
//! Freezing cannot be enforced by the compiler: the released crates pinned
//! `strata-common` at `v0.3.0-rc.2` while this workspace is on `v0.4.0-rc.2`,
//! and the two cannot coexist. Every file here was taken verbatim from tag
//! `v0.3.0-rc.2` (commit 45a1fa2) and adjusted only where the current
//! dependencies force it; each such adjustment is marked `DEVIATION`.
//!
//! What changed after these rules: `7e0b873` replaced immediate checkpoint
//! predicate replacement with range-keyed pending transitions. See
//! `strata-checkpoint-verification` for the current behaviour and
//! `migrate_from_v0` there for the conversion.

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

pub use errors::CheckpointValidationError;
pub use ssz_generated::ssz::state::CheckpointState;
// DEVIATION: `pub` rather than `pub(crate)`. The conversion into the current
// layout lives in the crate that owns that layout, so it must be able to read
// this one's fields. Visibility only; no layout or behaviour change.
pub use ssz_generated::ssz::state::DepositPool;
pub use verification::{CheckpointL1Range, verify_progression, verify_sequencer_predicate};
