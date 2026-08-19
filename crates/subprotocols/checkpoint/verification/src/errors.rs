use strata_btc_types::BitcoinAmount;
use strata_identifiers::{Buf32, Epoch};
use strata_predicate::PredicateError;
use thiserror::Error;

/// Result type for checkpoint subprotocol operations.
pub(crate) type CheckpointValidationResult<T> = Result<T, CheckpointValidationError>;

#[derive(Debug, Error)]
pub enum CheckpointValidationError {
    #[error("invalid checkpoint payload: {0}")]
    InvalidPayload(#[from] InvalidCheckpointPayload),

    /// The envelope pubkey does not match the sequencer key.
    #[error("invalid sequencer key: {0}")]
    InvalidSequencerKey(#[from] InvalidSequencerKey),
}

/// Sequencer key verification failed.
#[derive(Debug, Error)]
pub enum InvalidSequencerKey {
    /// Envelope pubkey does not match the stored sequencer key. The envelope side is an
    /// arbitrary-length script push, so this also covers a wrong length.
    #[error(
        "envelope pubkey mismatch: expected {}, got {}",
        expected,
        hex_encode(actual)
    )]
    PubkeyMismatch { expected: Buf32, actual: Vec<u8> },
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

    #[error("checkpoint L1 range {start}..={end} straddles predicate boundary {boundary}")]
    RangeStraddlesPredicateBoundary { start: u32, end: u32, boundary: u32 },

    /// Malformed withdrawal destination descriptor
    ///
    /// This error occurs when a withdrawal intent log contains a malformed
    /// destination descriptor. Since user funds have been destroyed on L2,
    /// this prevents the funds from being withdrawn on L1.
    #[error("malformed withdrawal destination descriptor")]
    MalformedWithdrawalDestDesc,

    /// Withdrawal amount exceeds the maximum Bitcoin money supply.
    #[error("withdrawal intent amount {sats} sat exceeds the Bitcoin money supply")]
    InvalidWithdrawalAmount { sats: u64 },

    /// Combined withdrawal amount exceeds the maximum Bitcoin money supply.
    #[error("combined withdrawal intent amount {sats} sat exceeds the Bitcoin money supply")]
    WithdrawalTotalTooLarge { sats: u128 },

    /// Epoch counter overflow.
    #[error("epoch overflow: verified tip epoch is at maximum value")]
    EpochOverflow,

    /// Withdrawal intents exceed the available bridge UTXO count.
    ///
    /// Returned when there are not enough available UTXOs to cover the requested withdrawal
    /// intents. The checkpoint is rejected to prevent the bridge from dispatching
    /// unassignable withdrawals.
    #[error(
        "withdrawal intents cannot be honored: insufficient UTXOs (available {available}, withdrawals require {required})"
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
        "withdrawal intent amount must be a positive multiple of denomination {expected}, got {actual}"
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
