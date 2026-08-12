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
/// - The Bridge proof system reconstructs this preimage to prove MMR membership, verifying that
///   operators have correctly fulfilled withdrawal obligations before allowing them to unlock
///   deposit UTXOs. That makes the encoding below a cross-repo consensus contract: changing it
///   invalidates every previously committed leaf.
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
    use proptest::prelude::*;

    use super::*;

    /// Pins the wire format that the Bridge proof system reconstructs out-of-repo: a 4-byte
    /// big-endian `deposit_idx` followed by the 32 key bytes, hashed to form the MMR leaf.
    #[test]
    fn encoding_is_stable() {
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

    proptest! {
        #[test]
        fn compute_hash_is_infallible(deposit_idx: u32, operator_pubkey: [u8; 32]) {
            let claim = OperatorClaimUnlock::new(deposit_idx, Buf32::from(operator_pubkey));
            // Should never panic for any input.
            let _hash = claim.compute_hash();
        }
    }
}
