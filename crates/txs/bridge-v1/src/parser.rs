use std::convert::TryInto;

use strata_asm_common::TxInputRef;

use crate::{
    constants::BridgeTxType,
    deposit::{DepositInfo, parse_deposit_tx},
    slash::{SlashInfo, parse_slash_tx},
    unstake::{UnstakeInfo, parse_unstake_tx},
    withdrawal_fulfillment::{WithdrawalFulfillmentInfo, parse_withdrawal_fulfillment_tx},
};

/// Represents a parsed transaction that can be either a deposit or withdrawal fulfillment.
#[derive(Debug, Clone)]
pub enum ParsedTx {
    /// A deposit transaction that locks Bitcoin funds in the bridge
    Deposit(DepositInfo),
    /// A withdrawal fulfillment transaction that releases Bitcoin funds from the bridge
    WithdrawalFulfillment(WithdrawalFulfillmentInfo),
    /// A slash transaction that penalizes a misbehaving operator
    Slash(SlashInfo),
    /// An unstake transaction to exit from the bridge
    Unstake(UnstakeInfo),
}

/// Parses a transaction into a structured format based on its type.
///
/// This function examines the transaction type from the tag and extracts relevant
/// information for bridge transactions that are directly processed by the subprotocol.
///
/// # Arguments
///
/// * `tx` - The transaction input reference to parse
///
/// # Returns
///
/// Returns `Some(ParsedTx)` for transaction types directly processed by the bridge
/// subprotocol (`Deposit`, `WithdrawalFulfillment`, `Slash`, `Unstake`) when the
/// transaction structure is well-formed.
///
/// Returns `None` when the transaction should be skipped, including:
/// - The transaction type is not directly processed (e.g., `DepositRequest` - fetched as auxiliary
///   data when its corresponding `Deposit` is encountered)
/// - The transaction type is not supported by the bridge subprotocol (e.g., `Commit`)
/// - The transaction tag has an unsupported type
/// - The transaction data extraction fails (malformed transaction structure)
pub fn parse_tx<'t>(tx: &'t TxInputRef<'t>) -> Option<ParsedTx> {
    match tx.tag().tx_type().try_into().ok()? {
        BridgeTxType::Deposit => {
            let info = parse_deposit_tx(tx).ok()?;
            Some(ParsedTx::Deposit(info))
        }
        BridgeTxType::WithdrawalFulfillment => {
            let info = parse_withdrawal_fulfillment_tx(tx).ok()?;
            Some(ParsedTx::WithdrawalFulfillment(info))
        }
        BridgeTxType::Slash => {
            let info = parse_slash_tx(tx).ok()?;
            Some(ParsedTx::Slash(info))
        }
        BridgeTxType::Unstake => {
            let info = parse_unstake_tx(tx).ok()?;
            Some(ParsedTx::Unstake(info))
        }
        // DepositRequest transactions are not parsed at this stage. They are requested as
        // auxiliary input during preprocessing when we encounter a `BridgeTxType::Deposit`
        // transaction, then parsed on-demand using `parse_drt()`.
        BridgeTxType::DepositRequest => None,
        // Commit transactions are not currently supported by the bridge subprotocol.
        BridgeTxType::Commit => None,
    }
}
