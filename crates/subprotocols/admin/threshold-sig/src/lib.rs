//! Threshold signature primitives for the Strata administration subprotocol.
//!
//! The administration subprotocol authorizes actions with M-of-N ECDSA signature sets
//! rather than a single key, so that governance keys can live on hardware wallets. This
//! crate holds the vocabulary for that scheme: who may sign ([`ThresholdConfig`]), how
//! that roster changes ([`ThresholdConfigUpdate`]), what a signer submits
//! ([`IndexedSignature`], [`SignatureSet`]), and how a set is checked
//! ([`verify_threshold_signatures`]).
//!
//! # Encoding
//!
//! [`ThresholdConfig`] is part of administration subprotocol state, which the ASM commits
//! to, so the SSZ layout of these types is consensus-critical. The layout is defined once in
//! `ssz/threshold.ssz`, and each type encodes by converting to the container generated from
//! that schema, so the wire format is correct by construction rather than hand-rolled. The
//! one exception is [`CompressedPublicKey`], which the schema models inline as `Bytes33`
//! and which therefore encodes directly as its bare 33-byte point.

// `ssz_derive`, `ssz_types`, `tree_hash` and `tree_hash_derive` are referenced only by the
// containers generated from `ssz/threshold.ssz`.
use ssz_derive as _;
use ssz_types as _;
use tree_hash as _;
use tree_hash_derive as _;

#[allow(
    clippy::all,
    unreachable_pub,
    missing_docs,
    clippy::allow_attributes,
    clippy::absolute_paths,
    reason = "generated code"
)]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

mod config;
mod errors;
mod keys;
mod signature;
mod ssz_bridge;
mod verification;

pub use config::{MAX_SIGNERS, ThresholdConfig, ThresholdConfigUpdate};
pub use errors::ThresholdSignatureError;
pub use keys::CompressedPublicKey;
pub use signature::{IndexedSignature, SignatureSet};
pub use verification::verify_threshold_signatures;
