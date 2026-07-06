//! ASM anchor state types.
//!
//! Owns the SSZ schemas and generated types for the ASM anchor state
//! ([`AnchorState`] and its components) along with the helpers on them that
//! do not depend on the subprotocol framework in `strata-asm-common`.

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
    pow::{
        BtcParams, BtcParamsRef, BtcWork, BtcWorkRef, HeaderVerificationState,
        HeaderVerificationStateRef, TimestampStore, TimestampStoreRef,
    },
    state::{
        AnchorState, AnchorStateRef, AsmHistoryAccumulatorState, AsmHistoryAccumulatorStateRef,
        ChainViewState, ChainViewStateRef, SectionState, SectionStateRef,
    },
};
