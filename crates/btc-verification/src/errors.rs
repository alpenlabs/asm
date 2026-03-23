use std::io;

use bitcoin::BlockHash;
use strata_identifiers::L1BlockId;
use thiserror::Error;

/// Errors that can occur during Bitcoin header verification.
#[derive(Debug, Error)]
pub enum L1VerificationError {
    /// Occurs when the previous block hash in the header does not match the expected hash.
    #[error("Block continuity error: expected previous block hash {expected:?}, got {found:?}")]
    ContinuityError {
        expected: L1BlockId,
        found: L1BlockId,
    },

    /// Occurs when the header's encoded target does not match the expected target.
    #[error(
        "Invalid Proof-of-Work: header target {found:?} does not match expected target {expected:?}"
    )]
    PowMismatch { expected: u32, found: u32 },

    /// Occurs when the computed block hash does not meet the target difficulty.
    #[error("Proof-of-Work not met: block hash {block_hash:?} does not meet target {target:?}")]
    PowNotMet { block_hash: BlockHash, target: u32 },

    /// Occurs when the header's timestamp is not greater than the median of the previous 11
    /// timestamps.
    #[error("Invalid timestamp: header time {time} is not greater than median {median}")]
    TimestampError { time: u32, median: u32 },

    /// Occurs when the new headers provided in a reorganization are fewer than the headers being
    /// removed.
    #[error(
        "Reorg error: new headers length {new_headers} is less than old headers length {old_headers}"
    )]
    ReorgLengthError {
        new_headers: usize,
        old_headers: usize,
    },

    /// Wraps underlying I/O errors.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Errors that can occur during block body verification.
#[derive(Debug, Error)]
pub enum L1BodyError {
    /// The block contains no transactions.
    #[error("block has no transactions")]
    EmptyBlock,

    /// The first transaction is not a coinbase transaction.
    #[error("first transaction is not a coinbase")]
    NotCoinbase,

    /// A witness commitment exists but no coinbase inclusion proof was provided.
    #[error("missing coinbase inclusion proof for segwit block")]
    MissingInclusionProof,

    /// The coinbase witness data is malformed (expected exactly one 32-byte element).
    #[error("invalid coinbase witness data")]
    InvalidCoinbaseWitness,

    /// The computed witness commitment does not match the one in the coinbase.
    #[error("witness commitment mismatch")]
    WitnessCommitmentMismatch,

    /// The coinbase inclusion proof does not verify against the header's merkle root.
    #[error("invalid coinbase inclusion proof")]
    InvalidInclusionProof,

    /// The merkle root in the header does not match the computed merkle root.
    #[error("merkle root mismatch")]
    MerkleRootMismatch,
}
