use strata_btc_types::BitcoinAmount;
use strata_identifiers::Epoch;
use strata_predicate::{PredicateError, PredicateTypeId};
use thiserror::Error;

/// Result type for checkpoint subprotocol operations.
pub(crate) type CheckpointValidationResult<T> = Result<T, CheckpointValidationError>;

#[derive(Debug, Error)]
pub enum CheckpointValidationError {
    #[error("invalid checkpoint payload: {0}")]
    InvalidPayload(#[from] InvalidCheckpointPayload),

    /// The sequencer predicate is invalid or does not match the envelope.
    #[error("invalid sequencer predicate: {0}")]
    InvalidSequencerPredicate(#[from] InvalidSequencerPredicate),
}

/// Sequencer predicate verification failed.
#[derive(Debug, Error)]
pub enum InvalidSequencerPredicate {
    /// Envelope pubkey does not match the sequencer predicate's condition bytes.
    #[error(
        "envelope pubkey mismatch: expected {}, got {}",
        hex_encode(expected),
        hex_encode(actual)
    )]
    PubkeyMismatch { expected: Vec<u8>, actual: Vec<u8> },

    /// Sequencer predicate is set to `NeverAccept`; no checkpoint can pass.
    #[error("sequencer predicate is NeverAccept")]
    NeverAccept,

    /// Sequencer predicate type is not valid for envelope authentication.
    #[error("unsupported sequencer predicate type: {0}")]
    UnsupportedType(PredicateTypeId),

    /// Sequencer predicate has an unknown type ID.
    #[error("unknown sequencer predicate type ID: {0}")]
    UnknownPredicateType(u8),
}

/// CheckpointPayload is invalid.
#[derive(Debug, Error)]
pub enum InvalidCheckpointPayload {
    /// Predicate verification failed.
    #[error("checkpoint predicate verification failed: {0}")]
    CheckpointPredicateVerification(PredicateError),

    /// Checkpoint epoch does not match expected progression.
    ///
    /// Each checkpoint must advance the epoch by exactly 1.
    #[error("invalid epoch: (expected {expected}, got {actual})")]
    InvalidEpoch { expected: Epoch, actual: Epoch },

    /// Checkpoint L1 height regresses below the last verified height.
    ///
    /// A checkpoint may cover the same L1 height as its predecessor (zero L1
    /// progress), but it must never claim a lower height.
    #[error(
        "checkpoint L1 height regresses: new checkpoint covers up to L1 height {new_height}, but previous checkpoint already covered up to L1 height {prev_height}"
    )]
    L1HeightRegresses { prev_height: u32, new_height: u32 },

    /// Checkpoint L1 height exceeds current block.
    ///
    /// This error occurs when a checkpoint claims to have processed L1 blocks
    /// up to a height that is greater than or equal to the L1 block height
    /// currently being applied in the ASM STF. Since the checkpoint transaction
    /// itself is contained in the L1 block at `current_height`, it can only
    /// reference L1 blocks that were processed **before** this block (i.e., up
    /// to `current_height - 1`).
    #[error("checkpoint L1 height {checkpoint_height} exceeds current block {current_height}")]
    CheckpointBeyondL1Tip {
        checkpoint_height: u32,
        current_height: u32,
    },

    /// L2 slot does not advance.
    #[error(
        "L2 slot must advance: new slot {new_slot} is not greater than previous slot {prev_slot}"
    )]
    L2SlotDoesNotAdvance { prev_slot: u64, new_slot: u64 },

    /// Malformed withdrawal destination descriptor
    ///
    /// This error occurs when a withdrawal intent log contains a malformed
    /// destination descriptor. Since user funds have been destroyed on L2,
    /// this prevents the funds from being withdrawn on L1.
    #[error("malformed withdrawal destination descriptor")]
    MalformedWithdrawalDestDesc,

    /// Epoch counter overflow.
    #[error("epoch overflow: verified tip epoch is at maximum value")]
    EpochOverflow,

    /// Withdrawal intents exceed the available bridge UTXO count.
    ///
    /// Returned when there are not enough available UTXOs to cover the requested withdrawal
    /// intents. The checkpoint is rejected to prevent the bridge from dispatching
    /// unassignable withdrawals.
    #[error(
        "withdrawal intents cannot be honored: insufficient UTXOs (available {available} sat, withdrawals require {required} sat)"
    )]
    InsufficientFunds {
        available: BitcoinAmount,
        required: BitcoinAmount,
    },

    /// A withdrawal intent's amount is not a positive multiple of the bridge denomination.
    ///
    /// The bridge has a single deposit denomination; every withdrawal intent must carry a
    /// positive integer multiple of that amount. Mismatches indicate either a malformed
    /// intent from OL or a bug upstream of the checkpoint subprotocol.
    #[error(
        "withdrawal intent amount must be a positive multiple of denomination {expected} sat, got {actual} sat"
    )]
    DenominationMismatch {
        expected: BitcoinAmount,
        actual: BitcoinAmount,
    },
}

/// Encode bytes as a hex string for error display.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").unwrap();
            s
        })
}
