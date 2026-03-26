//! Bitcoin header verification and utilities.

mod body_verification;
mod errors;
mod header_verification;
mod inclusion_proof;
mod timestamp_store;
mod utils_btc;
mod work;

pub use body_verification::check_block_integrity;
pub use errors::{L1BodyError, L1VerificationError};
pub use header_verification::{HeaderVerificationState, get_relative_difficulty_adjustment_height};
pub use inclusion_proof::TxidInclusionProof;
pub use timestamp_store::TimestampStore;
pub use utils_btc::{compute_block_hash, compute_txid, compute_wtxid};
pub use work::BtcWork;
