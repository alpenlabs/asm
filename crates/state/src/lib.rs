//! ASM anchor state types.
//!
//! Owns the SSZ schemas and generated types for the ASM anchor state
//! ([`AnchorState`] and its components) along with the helpers on them that
//! do not depend on the subprotocol framework in `strata-asm-common`.

// Not referenced from code, but the SSZ build script resolves the
// `strata_identifiers` schema imports through this dependency.
use strata_identifiers as _;

mod mmr;
mod state;

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

pub use mmr::*;
pub use ssz_generated::ssz::{
    self as ssz,
    state::{
        AnchorState, AnchorStateRef, AsmHistoryAccumulatorState, AsmHistoryAccumulatorStateRef,
        ChainViewState, ChainViewStateRef, SectionState, SectionStateRef,
    },
};
// Re-exported so downstream crates keep a single import path for the anchor
// state and its components; the pow state is the native verifier type now.
pub use strata_btc_verification::{HeaderVerificationState, HeaderVerificationStateRef};
