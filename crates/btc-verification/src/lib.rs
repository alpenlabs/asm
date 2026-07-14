//! Bitcoin header verification and utilities.

/// SSZ delegate types generated from `ssz/header_verification.ssz`.
#[cfg(feature = "ssz")]
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

mod body_verification;
mod errors;
mod header_verification;
mod inclusion_proof;
#[cfg(feature = "ssz")]
mod ssz_delegate;
mod timestamp_store;
mod utils_btc;
mod work;

pub use body_verification::check_block_integrity;
pub use errors::{L1BodyError, L1VerificationError};
pub use header_verification::{
    HeaderVerificationState, L1Anchor, get_relative_difficulty_adjustment_height,
};
pub use inclusion_proof::TxidInclusionProof;
#[cfg(feature = "ssz")]
pub use ssz_delegate::HeaderVerificationStateRef;
pub use timestamp_store::{TIMESTAMPS_FOR_MEDIAN, TimestampStore};
pub use utils_btc::{compute_block_hash, compute_txid, compute_wtxid};
pub use work::BtcWork;
