use bitcoin::ScriptBuf;
use strata_asm_proto_bridge_v1_txs::errors::{Mismatch, TxStructureError};
use strata_asm_proto_bridge_v1_types::OperatorBitmapError;
use thiserror::Error;

/// Errors that can occur when validating deposit transactions at the subprotocol level.
///
/// These errors represent state-level validation failures that occur after successful
/// transaction parsing and cryptographic validation.
#[derive(Debug, Error)]
pub enum DepositValidationError {
    /// The deposit output is not locked to the expected aggregated operator key.
    #[error("Deposit output lock mismatch {0}")]
    WrongOutputLock(Mismatch<ScriptBuf>),

    /// Deposit output lock validation failed.
    #[error("Deposit output lock validation failed: {0}")]
    DepositOutput(#[from] DepositOutputError),

    /// The deposit amount does not match the expected amount for this bridge configuration.
    #[error("Invalid deposit amount {0}")]
    MismatchDepositAmount(Mismatch<u64>),

    /// A deposit with this index already exists in the deposits table.
    /// This should not occur since deposit indices are guaranteed unique by the N/N multisig.
    #[error("Deposit index {0} already exists in deposits table")]
    DepositIdxAlreadyExists(u32),

    /// The DRT output script does not match the expected locking script.
    #[error("DRT output script mismatch {0}")]
    DrtOutputScriptMismatch(Mismatch<ScriptBuf>),

    /// Failed to parse the Deposit Request Transaction.
    #[error("failed to parse DRT: {0}")]
    DrtParseError(#[from] TxStructureError),
}

/// Errors that can occur during deposit output lock validation.
#[derive(Debug, Error, Clone)]
pub enum DepositOutputError {
    /// The operator public key is malformed or invalid.
    #[error("Invalid operator public key")]
    InvalidOperatorKey,

    /// The deposit output is not locked to the expected aggregated operator key.
    #[error("Deposit output is not locked to the aggregated operator key")]
    WrongOutputLock,

    /// Missing deposit output at the expected index.
    #[error("Missing deposit output at index {0}")]
    MissingDepositOutput(usize),
}

/// Errors that can occur when creating or managing withdrawal assignments.
///
/// Covers the full withdrawal-assignment flow: locating an unassigned deposit,
/// matching the withdrawal amount, selecting an eligible operator, and updating
/// the operator bitmap.
#[derive(Debug, Error)]
pub enum WithdrawalAssignmentError {
    /// No unassigned deposits are available for processing.
    #[error("No unassigned deposits available for withdrawal processing")]
    NoUnassignedDeposits,

    /// Deposit amount doesn't match the requested withdrawal amount.
    #[error("Deposit amount mismatch {0}")]
    DepositWithdrawalAmountMismatch(Mismatch<u64>),

    /// No eligible operators found for the deposit.
    #[error(
        "No current multisig operator found in deposit's notary operators for deposit index {deposit_idx}"
    )]
    NoEligibleOperators { deposit_idx: u32 },

    /// Bitmap operation failed.
    #[error("Bitmap operation failed: {0}")]
    BitmapError(#[from] OperatorBitmapError),
}
