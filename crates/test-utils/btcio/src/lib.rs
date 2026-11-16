//! Bitcoin transaction testing utilities.
//!
//! This crate provides utilities for testing Bitcoin transactions in regtest mode,
//! including funding, signing, and broadcasting transactions with support for both
//! single-key and MuSig2 multi-signature schemes.
//!
//! [`EnvelopeTx`] is the exception: it builds real SPS-50 commit/reveal transactions on any
//! network, and the admin CLI uses it too.

pub mod address;
pub mod client;
pub mod envelope;
pub mod funding;
pub mod harness;
pub mod mining;
pub mod signing;
pub mod submit;
pub mod transaction;
pub mod utils;

// Re-export commonly used functions
pub use client::{get_bitcoind_and_client, get_bitcoind_and_client_with_txindex};
pub use envelope::{EnvelopeTx, EnvelopeTxError, random_keypair};
pub use harness::BtcioTestHarness;
pub use mining::mine_blocks;
pub use submit::{submit_transaction_with_key, submit_transaction_with_keys};
pub use transaction::broadcast_transaction;
