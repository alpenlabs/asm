//! Withdrawal types
//!
//! [`WithdrawalIntent`] is a user's request to withdraw funds — destination, amount, and a
//! preferred operator. The bridge consumes it to create an assignment, retaining only the
//! [`WithdrawalOutput`] (destination + amount) that the assigned operator must pay out.

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

    /// Returns the Bitcoin output for this withdrawal — its destination and amount, without
    /// the operator preference.
    pub fn to_output(&self) -> WithdrawalOutput {
        WithdrawalOutput::new(self.destination.clone(), self.amt)
    }
}

/// The Bitcoin output a fulfilled withdrawal must create: a destination and an amount.
///
/// This is the per-assignment payout an operator pays out, as opposed to [`WithdrawalIntent`] —
/// the user's request, which also carries an operator preference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct WithdrawalOutput {
    /// Bitcoin Output Script Descriptor specifying the destination address.
    pub destination: Descriptor,

    /// Amount to withdraw (in satoshis).
    pub amt: BitcoinAmount,
}

impl WithdrawalOutput {
    /// Creates a new withdrawal output with the specified destination and amount.
    pub fn new(destination: Descriptor, amt: BitcoinAmount) -> Self {
        Self { destination, amt }
    }

    /// Returns a reference to the destination descriptor.
    pub fn destination(&self) -> &Descriptor {
        &self.destination
    }

    /// Returns the withdrawal amount.
    pub fn amt(&self) -> BitcoinAmount {
        self.amt
    }
}
