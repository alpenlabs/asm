use std::fmt::Debug;

use bitcoin::ScriptBuf;
use strata_asm_proto_bridge_v1_txs::errors::{Mismatch, TxStructureError};
use strata_asm_proto_bridge_v1_types::{OperatorBitmapError, OperatorIdx};
use strata_btc_types::BitcoinAmount;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeSubprotocolError {
    #[error("failed to process deposit tx: {0}")]
    DepositTxProcess(#[from] DepositValidationError),

    #[error("failed to parse withdrawal fulfillment tx: {0}")]
    WithdrawalTxProcess(#[from] WithdrawalValidationError),

    #[error("failed to validate slash tx: {0}")]
    SlashTxValidation(#[from] SlashValidationError),

    #[error("failed to validate unstake tx: {0}")]
    UnstakeTxValidation(#[from] UnstakeValidationError),
}

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

/// Errors that can occur when validating withdrawal fulfillment transactions.
///
/// When these validation errors occur, they are logged and the transaction is skipped.
/// No further processing is performed on transactions that fail to validate.
#[derive(Debug, Error)]
pub enum WithdrawalValidationError {
    /// No assignment found for the deposit
    #[error("No assignment found for deposit index {deposit_idx}")]
    NoAssignmentFound { deposit_idx: u32 },

    /// Withdrawal amount doesn't match assignment amount
    #[error("Withdrawal amount mismatch {0}")]
    AmountMismatch(Mismatch<BitcoinAmount>),

    /// Withdrawal destination doesn't match assignment destination
    #[error("Withdrawal destination mismatch {0}")]
    DestinationMismatch(Mismatch<ScriptBuf>),
}

#[derive(Debug, Error)]
pub enum SlashValidationError {
    /// Stake connector input is not locked to the expected N/N multisig script
    #[error("stake connector not locked to N/N multisig script")]
    InvalidStakeConnectorScript,

    /// The operator being slashed was not a member of the N/N multisig the stake connector is
    /// locked to. Carries the N/N script so the offending multisig can be identified later.
    #[error("operator {operator} is not part of the referenced N/N multisig {script:?}")]
    OperatorNotInMultisig {
        operator: OperatorIdx,
        script: ScriptBuf,
    },
}

#[derive(Debug, Error)]
pub enum UnstakeValidationError {
    /// The witness-pushed pubkey is not a historical N/N aggregated key of the operator set.
    #[error("unstake witness pubkey is not a historical N/N aggregated key")]
    UnknownNnKey,

    /// The spent prevout is not the canonical stake connector committing to the witness-derived
    /// `(stake_hash, N/N pubkey)`.
    #[error("spent prevout does not match the canonical stake connector scriptPubKey")]
    StakeConnectorMismatch,

    /// The operator being unstaked was not a member of the N/N multisig identified by the
    /// witness-pushed pubkey. Carries the N/N script so the offending multisig can be identified
    /// later.
    #[error("operator {operator} is not part of the referenced N/N multisig {script:?}")]
    OperatorNotInMultisig {
        operator: OperatorIdx,
        script: ScriptBuf,
    },
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
