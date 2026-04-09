use std::convert::TryInto;

use strata_asm_common::{
    TxInputRef,
    logging::{debug, warn},
};

use crate::{
    constants::BridgeTxType,
    deposit::{DepositInfo, parse_deposit_tx},
    errors::TxStructureError,
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
/// transaction structure is well-formed, returns None otherwise.
pub fn parse_tx<'t>(tx: &'t TxInputRef<'t>) -> Option<ParsedTx> {
    // Step 1: Decode the SPS-50 tag's tx type byte into a known `BridgeTxType`.
    // An unknown discriminant means the tag was tagged for the bridge subprotocol but with a
    // type this build doesn't recognize — likely a protocol/version mismatch, so warn and skip.
    let raw_tx_type = tx.tag().tx_type();
    let bridge_tx_type: BridgeTxType = match raw_tx_type.try_into() {
        Ok(t) => t,
        Err(e) => {
            // `tx_id` is computed inside the macro, because logging is compiled to noop in ZkVM.
            warn!(
                tx_id = %tx.tx().compute_txid(),
                raw_tx_type,
                error = %e,
                "Skipping tx with unsupported bridge tx type",
            );
            return None;
        }
    };

    // Step 2: Dispatch to the per-type parser. Variants that this function does not parse
    // here (`DepositRequest`, `Commit`) take a debug-logged early return; the rest produce a
    // `Result<ParsedTx, TxStructureError>` that's funnelled through the shared handler below.
    let result: Result<ParsedTx, TxStructureError> = match bridge_tx_type {
        BridgeTxType::Deposit => parse_deposit_tx(tx).map(ParsedTx::Deposit),
        BridgeTxType::WithdrawalFulfillment => {
            parse_withdrawal_fulfillment_tx(tx).map(ParsedTx::WithdrawalFulfillment)
        }
        BridgeTxType::Slash => parse_slash_tx(tx).map(ParsedTx::Slash),
        BridgeTxType::Unstake => parse_unstake_tx(tx).map(ParsedTx::Unstake),
        // DepositRequest transactions are not parsed at this stage. They are requested as
        // auxiliary input during preprocessing when we encounter a `BridgeTxType::Deposit`
        // transaction, then parsed on-demand using `parse_drt()`. This is expected behavior,
        // not an error, so we log at debug level only.
        BridgeTxType::DepositRequest => {
            debug!(
                tx_id = %tx.tx().compute_txid(),
                "Skipping DepositRequest tx; processed as auxiliary input for its Deposit",
            );
            return None;
        }
        // Commit transactions are not currently supported by the bridge subprotocol.
        BridgeTxType::Commit => {
            debug!(
                tx_id = %tx.tx().compute_txid(),
                "Skipping Commit tx; not supported by bridge subprotocol",
            );
            return None;
        }
    };

    // Step 3: Funnel parser failures through one shared log site. The tx type is already
    // encoded in `TxStructureError`'s Display impl, so we don't need to repeat it per arm.
    match result {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            warn!(
                tx_id = %tx.tx().compute_txid(),
                error = %e,
                "Failed to parse bridge tx; skipping",
            );
            None
        }
    }
}
