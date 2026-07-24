use bitcoin::ScriptBuf;
// Re-exported so downstream users keep finding the state-owned errors here.
pub use strata_asm_proto_bridge_v1_state::{
    DepositOutputError, DepositValidationError, WithdrawalAssignmentError,
};
use strata_asm_proto_bridge_v1_txs::errors::Mismatch;
use strata_asm_proto_bridge_v1_types::OperatorIdx;
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
