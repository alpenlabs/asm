use bitcoin::BlockHash;
use strata_identifiers::L1BlockId;
use thiserror::Error;

/// Errors that can occur during Bitcoin header verification.
#[derive(Debug, Error)]
pub enum L1VerificationError {
    /// The previous block hash in the header does not match the expected hash.
    #[error("mismatched parent blockid (expected {expected:?}, found {found:?})")]
    ContinuityError {
        expected: L1BlockId,
        found: L1BlockId,
    },

    /// The header's encoded target does not match the expected target.
    #[error("header has incorrect difficulty target (expected {expected:?}, found {found:?})")]
    PowMismatch { expected: u32, found: u32 },

    /// The computed block hash does not meet the target difficulty.
    #[error("block {block_hash:?} does not meet target difficulty {target}")]
    PowNotMet { block_hash: BlockHash, target: u32 },

    /// The header's timestamp is not greater than the median of the previous 11 timestamps.
    #[error("header timestamp {time} not greater than median {median}")]
    TimestampError { time: u32, median: u32 },
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
