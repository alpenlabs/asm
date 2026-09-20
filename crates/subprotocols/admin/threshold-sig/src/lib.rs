//! Threshold signature primitives for the Strata administration subprotocol.
//!
//! The administration subprotocol authorizes actions with M-of-N ECDSA signature sets
//! rather than a single key, so that governance keys can live on hardware wallets. This
//! crate holds the vocabulary for that scheme: who may sign ([`ThresholdConfig`]), how
//! that set of signers changes ([`ThresholdConfigUpdate`]), what a signer submits
//! ([`IndexedSignature`], [`SignatureSet`]), and how a set is checked
//! ([`verify_threshold_signatures`]).
//!
//! Signers are named by [`P2wpkhAddress`] rather than by public key, because a hardware
//! wallet will display an address but not a compressed point. Verification recovers the
//! public key from each signature and compares its address against the configured one.
//!
//! # Encoding
//!
//! [`ThresholdConfig`] is part of administration subprotocol state, and
//! [`ThresholdConfigUpdate`] and [`SignatureSet`] travel in administration transactions, so
//! the SSZ layout of these types is consensus-critical. Each derives that layout from its
//! field order, and a byte-layout test beside each one pins it against an accidental
//! reorder. [`P2wpkhAddress`] encodes as its bare 20-byte witness program.
//!
//! Decoding checks layout, not meaning: it does not re-run the constructors. Encoded
//! configurations come only from state this crate wrote and the ASM proof binds, and the two
//! types that do arrive from transactions are re-validated by whatever consumes them —
//! [`ThresholdConfig::apply_update`] for an update, and [`verify_threshold_signatures`] for a
//! signature set.

mod address;
mod config;
mod errors;
mod signature;
mod ssz_adapters;
mod verification;

pub use address::{NotP2wpkhAddress, P2wpkhAddress};
pub use config::{MAX_SIGNERS, ThresholdConfig, ThresholdConfigUpdate};
pub use errors::ThresholdSignatureError;
pub use signature::{IndexedSignature, SignatureSet};
pub use ssz_adapters::non_zero_u8;
pub use verification::verify_threshold_signatures;
