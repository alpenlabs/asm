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

/// Bitcoin output specification for a withdrawal operation.
///
/// Each withdrawal output specifies a destination address (as a Bitcoin descriptor)
/// and the amount to be sent. This structure provides all information needed by
/// operators to construct the appropriate Bitcoin transaction output.
///
/// # Bitcoin Descriptors
///
/// The destination uses Bitcoin Output Script Descriptors (BOSD), which provide
/// a standardized way to specify Bitcoin addresses and locking conditions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct WithdrawOutput {
    /// Bitcoin Output Script Descriptor specifying the destination address.
    #[ssz(with = "descriptor_ssz")]
    pub destination: Descriptor,

    /// Amount to withdraw (in satoshis).
    pub amt: BitcoinAmount,
}

impl WithdrawOutput {
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

/// Command specifying a Bitcoin output for a withdrawal operation.
///
/// This structure instructs operators on how to construct the Bitcoin transaction
/// output when processing a withdrawal. It currently contains a single output specifying the
/// destination and amount, along with the operator fee that will be deducted.
///
/// ## Fee Structure
///
/// The operator fee is deducted from the withdrawal amount before creating the Bitcoin
/// output. This means the user receives the net amount (withdrawal amount minus operator
/// fee) in their Bitcoin transaction, while the operator keeps the fee as compensation
/// for processing the withdrawal.
///
/// ## Future Enhancements
///
/// - **Batching**: Support for multiple outputs in a single withdrawal command to enable efficient
///   processing of multiple withdrawals in one Bitcoin transaction
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct WithdrawalCommand {
    /// Bitcoin output to create in the withdrawal transaction.
    output: WithdrawOutput,

    /// Amount the operator can take as fees for processing withdrawal.
    operator_fee: BitcoinAmount,
}

impl WithdrawalCommand {
    /// Creates a new withdrawal command with the specified output and operator fee.
    pub fn new(output: WithdrawOutput, operator_fee: BitcoinAmount) -> Self {
        Self {
            output,
            operator_fee,
        }
    }

    /// Returns a reference to the destination descriptor for this withdrawal.
    pub fn destination(&self) -> &Descriptor {
        &self.output.destination
    }

    /// Updates the operator fee for this withdrawal command.
    pub fn update_fee(&mut self, new_fee: BitcoinAmount) {
        self.operator_fee = new_fee
    }

    /// Calculates the net amount the user will receive after operator fee deduction.
    ///
    /// This is the amount that will actually be sent to the user's Bitcoin address,
    /// which equals the withdrawal amount minus the operator fee.
    pub fn net_amount(&self) -> BitcoinAmount {
        self.output.amt().saturating_sub(self.operator_fee)
    }
}

#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod descriptor_ssz {
    use super::Descriptor;

    pub mod encode {
        use ssz::Encode as SszEncode;

        use super::Descriptor;

        pub fn is_ssz_fixed_len() -> bool {
            <Vec<u8> as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <Vec<u8> as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &Descriptor) -> usize {
            value.to_bytes().ssz_bytes_len()
        }

        pub fn ssz_append(value: &Descriptor, buf: &mut Vec<u8>) {
            value.to_bytes().ssz_append(buf);
        }
    }

    pub mod decode {
        use ssz::{Decode as SszDecode, DecodeError};

        use super::Descriptor;

        pub fn is_ssz_fixed_len() -> bool {
            <Vec<u8> as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <Vec<u8> as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Descriptor, DecodeError> {
            let descriptor_bytes = Vec::<u8>::from_ssz_bytes(bytes)?;
            Descriptor::from_bytes(&descriptor_bytes)
                .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    #[test]
    fn withdraw_output_ssz_roundtrip() {
        let mut arb = ArbitraryGenerator::new();
        let original: WithdrawOutput = arb.generate();
        let encoded = original.as_ssz_bytes();
        let decoded = WithdrawOutput::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
