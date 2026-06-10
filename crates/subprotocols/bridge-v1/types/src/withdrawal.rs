//! Withdrawal Command Management
//!
//! This module contains types for specifying withdrawal commands and outputs.
//! Withdrawal commands define the Bitcoin outputs that operators should create
//! when processing withdrawal requests from deposits.

use arbitrary::Arbitrary;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_btc_types::BitcoinAmount;

use crate::OperatorSelection;

/// Bitcoin output specification for a withdrawal operation.
///
/// Each withdrawal output specifies a destination address (as a Bitcoin descriptor),
/// the amount to be sent, and the user's operator selection for who should fulfill
/// the withdrawal. This structure provides all information needed by the bridge to
/// assign and construct the appropriate Bitcoin transaction output.
///
/// # Bitcoin Descriptors
///
/// The destination uses Bitcoin Output Script Descriptors (BOSD), which provide
/// a standardized way to specify Bitcoin addresses and locking conditions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct WithdrawOutput {
    /// Bitcoin Output Script Descriptor specifying the destination address.
    pub destination: Descriptor,

    /// Amount to withdraw (in satoshis).
    pub amt: BitcoinAmount,

    /// User's operator selection for withdrawal assignment.
    pub selected_operator: OperatorSelection,
}

impl WithdrawOutput {
    /// Creates a new withdrawal output with the specified destination, amount, and operator
    /// selection.
    pub fn new(
        destination: Descriptor,
        amt: BitcoinAmount,
        selected_operator: OperatorSelection,
    ) -> Self {
        Self {
            destination,
            amt,
            selected_operator,
        }
    }

    /// Returns a reference to the destination descriptor.
    pub fn destination(&self) -> &Descriptor {
        &self.destination
    }

    /// Returns the withdrawal amount.
    pub fn amt(&self) -> BitcoinAmount {
        self.amt
    }

    /// Returns the operator selection.
    pub fn selected_operator(&self) -> OperatorSelection {
        self.selected_operator
    }
}
