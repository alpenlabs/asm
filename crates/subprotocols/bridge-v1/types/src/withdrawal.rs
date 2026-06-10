//! Withdrawal Intent
//!
//! This module defines [`WithdrawalIntent`], a user's request to withdraw funds from the
//! bridge. The bridge turns an intent into an operator assignment and, ultimately, a
//! Bitcoin withdrawal transaction.

use arbitrary::Arbitrary;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_btc_types::BitcoinAmount;

use crate::OperatorSelection;

/// A user's request to withdraw funds from the bridge.
///
/// Specifies the destination address (as a Bitcoin descriptor), the amount to send, and
/// the user's preferred operator to fulfill it. The bridge consumes an intent to create an
/// operator assignment and, ultimately, the Bitcoin withdrawal output.
///
/// # Bitcoin Descriptors
///
/// The destination uses Bitcoin Output Script Descriptors (BOSD), which provide
/// a standardized way to specify Bitcoin addresses and locking conditions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct WithdrawalIntent {
    /// Bitcoin Output Script Descriptor specifying the destination address.
    pub destination: Descriptor,

    /// Amount to withdraw (in satoshis).
    pub amt: BitcoinAmount,

    /// User's operator selection for withdrawal assignment.
    pub selected_operator: OperatorSelection,
}

impl WithdrawalIntent {
    /// Creates a new withdrawal intent with the specified destination, amount, and operator
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
