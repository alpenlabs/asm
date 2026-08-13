//! Withdrawal types
//!
//! [`WithdrawalIntent`] is a user's request to withdraw funds — destination, amount, and a
//! preferred operator. The bridge consumes it to create an assignment, retaining only the
//! [`WithdrawalOutput`] (destination + amount) that the assigned operator must pay out.
//!
//! Once an assignment is fulfilled, [`OperatorClaimUnlock`] authorizes the assigned operator to
//! unlock the corresponding deposit UTXO through the Bridge proof system.

use arbitrary::Arbitrary;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_btc_types::BitcoinAmount;
use strata_codec::{Codec, encode_to_vec};
use strata_crypto::hash;
use strata_identifiers::Buf32;

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

    /// Decomposes this intent into `N = amt / denomination` single-denomination intents.
    ///
    /// Each yielded intent carries `denomination` as its amount and inherits this intent's
    /// destination and operator selection. The intents are produced lazily as the iterator is
    /// consumed.
    ///
    /// Returns `None` if the amount is not a whole multiple of the denomination; the caller decides
    /// what such a mismatch means in its own error vocabulary.
    pub fn decompose(
        &self,
        denomination: BitcoinAmount,
    ) -> Option<impl Iterator<Item = WithdrawalIntent>> {
        let amt = self.amt.to_sat();
        let denom = denomination.to_sat();

        if !amt.is_multiple_of(denom) {
            return None;
        }

        let n = amt / denom;
        let destination = self.destination.clone();
        let selected_operator = self.selected_operator;

        Some((0..n).map(move |_| {
            WithdrawalIntent::new(destination.clone(), denomination, selected_operator)
        }))
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

/// Represents an operator's claim to unlock a deposit UTXO after successful withdrawal fulfillment.
///
/// This structure is created when a withdrawal fulfillment transaction is successfully validated.
/// It serves as proof that a valid frontpayment was made matching the assignment specifications,
/// and authorizes the assigned operator to claim the corresponding locked deposit funds through
/// the Bridge proof system.
///
/// The claim contains:
/// - The deposit index that identifies which locked UTXO can be claimed
/// - The public key of the assigned operator who is authorized to claim
///
/// # Important Notes
///
/// - The `operator_pubkey` always identifies the **assigned operator** from the assignment entry,
///   not necessarily the party who made the actual frontpayment (since frontpayment identity is not
///   validated during transaction processing).
/// - Only the [hash](Self::compute_hash) of this structure leaves the ASM, emitted as an ASM log
///   via `NewExportEntry` and folded into the bridge export container's MMR. The structure itself
///   is never stored.
/// - This data is stored in the MohoState and emitted as an ASM log via `NewExportEntry`.
/// - The Bridge proof system consumes these entries to verify operators have correctly fulfilled
///   withdrawal obligations before allowing them to unlock deposit UTXOs.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
pub struct OperatorClaimUnlock {
    /// The index of the deposit that was fulfilled.
    pub deposit_idx: u32,

    /// BIP-340 x-only serialization of the assigned operator's MuSig2 public key
    /// ([`EvenPublicKey`](strata_crypto::EvenPublicKey)), resolved from the operator table when
    /// the fulfillment is processed.
    pub operator_pubkey: Buf32,
}

impl OperatorClaimUnlock {
    pub fn new(deposit_idx: u32, operator_pubkey: Buf32) -> Self {
        Self {
            deposit_idx,
            operator_pubkey,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let buf = encode_to_vec(self).expect("failed to encode OperatorClaimUnlock");
        hash::raw(&buf).0
    }
}

#[cfg(test)]
mod tests {
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    #[test]
    fn decompose_splits_into_denomination_units() {
        let mut arb = ArbitraryGenerator::new();
        let denomination = BitcoinAmount::try_from(10_000)
            .expect("test amount must be within the Bitcoin money supply");

        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = BitcoinAmount::try_from(denomination.to_sat() * 3)
            .expect("test amount must be within the Bitcoin money supply");

        let intents: Vec<WithdrawalIntent> = intent.decompose(denomination).unwrap().collect();

        assert_eq!(intents.len(), 3);
        // Each unit carries the denomination and inherits the batch's destination and selection.
        for unit in &intents {
            assert_eq!(unit.amt(), denomination);
            assert_eq!(unit.destination(), intent.destination());
            assert_eq!(unit.selected_operator(), intent.selected_operator());
        }
    }

    #[test]
    fn decompose_non_multiple_returns_none() {
        let mut arb = ArbitraryGenerator::new();
        let denomination = BitcoinAmount::try_from(10_000)
            .expect("test amount must be within the Bitcoin money supply");

        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = BitcoinAmount::try_from(denomination.to_sat() + 1)
            .expect("test amount must be within the Bitcoin money supply");

        assert!(intent.decompose(denomination).is_none());
    }

    #[test]
    fn operator_claim_unlock_encoding_is_stable() {
        use strata_codec::encode_to_vec;

        let claim = OperatorClaimUnlock::new(1, Buf32::from([2u8; 32]));

        let mut expected = vec![0x00, 0x00, 0x00, 0x01];
        expected.extend_from_slice(&[2u8; 32]);

        assert_eq!(encode_to_vec(&claim).unwrap(), expected);

        // Pinned literal rather than a recomputed `hash::raw`, so that a change to the hash
        // function itself is caught here instead of silently invalidating committed leaves.
        assert_eq!(
            hex::encode(claim.compute_hash()),
            "3620517d4d610f1d90942db87e2780cfed7c2fb8322300d23b05f546ec8dec74"
        );
    }

    proptest::proptest! {
        #[test]
        fn operator_claim_unlock_compute_hash_is_infallible(
            deposit_idx: u32,
            operator_pubkey: [u8; 32],
        ) {
            let claim = OperatorClaimUnlock::new(deposit_idx, Buf32::from(operator_pubkey));
            // Should never panic for any input.
            let _hash = claim.compute_hash();
        }
    }
}
