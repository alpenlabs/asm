//! Operator claim types.
//!
//! Once an assignment is fulfilled, [`OperatorClaimUnlock`] authorizes the assigned operator to
//! unlock the corresponding deposit UTXO through the Bridge proof system.

use ssz::Encode as _;
use ssz_derive::{Decode, Encode};
use strata_crypto::hash;
use strata_identifiers::Buf32;

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
/// - The Bridge proof system consumes these entries to verify operators have correctly fulfilled
///   withdrawal obligations before allowing them to unlock deposit UTXOs. It reconstructs the claim
///   and recomputes the leaf to check its inclusion proof, so it has to agree with this type on
///   both the SSZ layout and the hash.
///
/// # Leaf hash
///
/// [`compute_hash`](Self::compute_hash) is sha256 over the SSZ encoding, and the MMR appends its
/// output verbatim. Both the layout and the hash are therefore consensus-visible: changing either
/// one moves every leaf, and with it the export container root at every height a fulfillment
/// landed.
///
/// A flat hash rather than the SSZ tree hash root, because merkleization only earns its cost when
/// a consumer proves one field of a container without the rest, and with two fields that both
/// reach the proof in full there is nothing to prove selectively.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
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

    /// Computes the export leaf committed for this claim: sha256 over the SSZ encoding.
    pub fn compute_hash(&self) -> [u8; 32] {
        hash::raw(&self.as_ssz_bytes()).0
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prop_assert_eq, proptest};
    use ssz::Decode as _;

    use super::*;

    #[test]
    fn operator_claim_unlock_ssz_roundtrip() {
        let claim = OperatorClaimUnlock::new(1, Buf32::from([2u8; 32]));

        let encoded = claim.as_ssz_bytes();

        // Both fields are fixed-size, so the container is 4 + 32 bytes with no offsets.
        let mut expected = vec![0x01, 0x00, 0x00, 0x00];
        expected.extend_from_slice(&[2u8; 32]);
        assert_eq!(encoded, expected);

        assert_eq!(
            OperatorClaimUnlock::from_ssz_bytes(&encoded).unwrap(),
            claim
        );
    }

    proptest! {
        /// The pinned vector above fixes one point of the layout; this covers the rest of the
        /// input space, where a field ordering or width mistake would otherwise only show up
        /// once a real claim hit it.
        #[test]
        fn operator_claim_unlock_ssz_roundtrips_for_any_value(
            deposit_idx: u32,
            operator_pubkey: [u8; 32],
        ) {
            let claim = OperatorClaimUnlock::new(deposit_idx, Buf32::from(operator_pubkey));

            let encoded = claim.as_ssz_bytes();

            prop_assert_eq!(encoded.len(), 36);
            prop_assert_eq!(OperatorClaimUnlock::from_ssz_bytes(&encoded).unwrap(), claim);
        }
    }

    #[test]
    fn operator_claim_unlock_leaf_hash_is_pinned() {
        let claim = OperatorClaimUnlock::new(1, Buf32::from([2u8; 32]));

        // Pinned literal rather than a recomputed `hash::raw`, so that a change to the hash
        // function itself is caught here instead of silently invalidating committed leaves.
        assert_eq!(
            hex::encode(claim.compute_hash()),
            "79525990a6761c9f3e4de9cd1a20c81183ecca4f3e1916ffe63c5fd60129ab82"
        );
    }
}
