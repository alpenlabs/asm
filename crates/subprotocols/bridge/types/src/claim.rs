//! Operator claim types.
//!
//! Once an assignment is fulfilled, [`OperatorClaimUnlock`] authorizes the assigned operator to
//! unlock the corresponding deposit UTXO through the Bridge proof system.

use ssz_derive::{Decode, Encode};
use strata_codec::{Codec, encode_to_vec};
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
/// - This data is stored in the MohoState and emitted as an ASM log via `NewExportEntry`.
/// - The Bridge proof system consumes these entries to verify operators have correctly fulfilled
///   withdrawal obligations before allowing them to unlock deposit UTXOs.
///
/// # Encodings
///
/// The two encodings this type carries are not interchangeable, and they disagree on the byte
/// layout because they order `deposit_idx` differently:
///
/// - [`Codec`] is what [`compute_hash`](Self::compute_hash) hashes, so it defines the export leaf
///   the MMR commits to. Changing that layout invalidates every leaf already committed.
/// - SSZ is how the value travels to the bridge proof, which takes it as an input field rather than
///   as a hash. Nothing commits to it.
#[derive(Debug, Clone, PartialEq, Eq, Codec, Encode, Decode)]
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
    use ssz::{Decode as _, Encode as _};

    use super::*;

    #[test]
    fn operator_claim_unlock_ssz_roundtrip() {
        let claim = OperatorClaimUnlock::new(1, Buf32::from([2u8; 32]));

        let encoded = claim.as_ssz_bytes();

        // Both fields are fixed-size, so the container is 4 + 32 bytes with no offsets. The index
        // is little-endian here and big-endian under `Codec`, which is why the leaf hash must keep
        // using the codec form.
        let mut expected = vec![0x01, 0x00, 0x00, 0x00];
        expected.extend_from_slice(&[2u8; 32]);
        assert_eq!(encoded, expected);

        assert_eq!(
            OperatorClaimUnlock::from_ssz_bytes(&encoded).unwrap(),
            claim
        );
    }

    #[test]
    fn operator_claim_unlock_encoding_is_stable() {
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
