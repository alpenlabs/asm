//! Operator claim types.
//!
//! Once an assignment is fulfilled, an operator claim authorizes the assigned operator to unlock
//! the corresponding deposit UTXO through the Bridge proof system. Only the claim's hash leaves
//! the ASM, emitted as an ASM log via `NewExportEntry` and appended verbatim to the bridge export
//! container's MMR.
//!
//! That hash is consensus state, so the claim is versioned rather than edited in place:
//!
//! - [`OperatorClaimUnlockV0`] is the format deployed chains have already committed leaves under.
//!   It is frozen, and `BridgeSubprotoV1` commits it.
//! - [`OperatorClaimUnlockV1`] names the assignee by public key instead of by table index. It is
//!   committed by `BridgeSubprotoV2`. Reaching it on a live chain takes a spec activation, since
//!   switching moves every subsequent leaf.

use ssz::Encode as _;
use ssz_derive::{Decode, Encode};
use strata_codec::{Codec, encode_to_vec};
use strata_crypto::hash;
use strata_identifiers::Buf32;

use crate::OperatorIdx;

/// An operator's claim to unlock a deposit UTXO after a successful withdrawal fulfillment, as
/// committed by chains running the v0 bridge subprotocol.
///
/// The claim is created when a withdrawal fulfillment transaction validates. It serves as proof
/// that a valid frontpayment was made matching the assignment specifications, and authorizes the
/// assigned operator to claim the corresponding locked deposit funds through the Bridge proof
/// system.
///
/// # Important Notes
///
/// - The `operator_idx` always refers to the **assigned operator** from the assignment entry, not
///   necessarily the party who made the actual frontpayment (since frontpayment identity is not
///   validated during transaction processing).
/// - Resolving the index back to an operator needs the operator table at the height the fulfillment
///   landed. [`OperatorClaimUnlockV1`] exists because the Bridge proof system has no such table,
///   and so cannot bind this claim to the key that signed for it.
/// - The Bridge proof system consumes these entries to verify operators have correctly fulfilled
///   withdrawal obligations before allowing them to unlock deposit UTXOs.
///
/// # Leaf hash
///
/// [`compute_hash`](Self::compute_hash) is sha256 over the [`Codec`] encoding — two big-endian
/// `u32`s, an 8-byte preimage. Deployed chains have committed leaves under exactly this
/// construction, so neither the field order, the codec, nor the hash may move.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
pub struct OperatorClaimUnlockV0 {
    /// The index of the deposit that was fulfilled.
    pub deposit_idx: u32,

    /// The index of the operator who was assigned to (and is authorized to claim) this withdrawal.
    pub operator_idx: OperatorIdx,
}

impl OperatorClaimUnlockV0 {
    pub fn new(deposit_idx: u32, operator_idx: OperatorIdx) -> Self {
        Self {
            deposit_idx,
            operator_idx,
        }
    }

    /// Computes the export leaf committed for this claim: sha256 over the [`Codec`] encoding.
    pub fn compute_hash(&self) -> [u8; 32] {
        let buf = encode_to_vec(self).expect("failed to encode OperatorClaimUnlockV0");
        hash::raw(&buf).0
    }
}

/// The successor to [`OperatorClaimUnlockV0`], naming the assignee by public key.
///
/// An operator index only means something next to the operator table at the height the
/// fulfillment landed, which the Bridge proof system does not carry. Holding the key directly lets
/// the proof bind a leaf to the operator that signed for it, without a table lookup.
///
/// # Important Notes
///
/// - The `operator_pubkey` always identifies the **assigned operator** from the assignment entry,
///   not necessarily the party who made the actual frontpayment (since frontpayment identity is not
///   validated during transaction processing).
/// - `BridgeSubprotoV2` commits this version, but no chain runs a ruleset that invokes it, so the
///   format below is not yet consensus state and can still be changed until one activates.
///
/// # Leaf hash
///
/// [`compute_hash`](Self::compute_hash) is sha256 over the SSZ encoding, and the MMR would append
/// its output verbatim. A flat hash rather than the SSZ tree hash root, because merkleization only
/// earns its cost when a consumer proves one field of a container without the rest, and with two
/// fields that both reach the proof in full there is nothing to prove selectively.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OperatorClaimUnlockV1 {
    /// The index of the deposit that was fulfilled.
    pub deposit_idx: u32,

    /// BIP-340 x-only serialization of the assigned operator's MuSig2 public key
    /// ([`EvenPublicKey`](strata_crypto::EvenPublicKey)), resolved from the operator table when
    /// the fulfillment is processed.
    pub operator_pubkey: Buf32,
}

impl OperatorClaimUnlockV1 {
    pub fn new(deposit_idx: u32, operator_pubkey: Buf32) -> Self {
        Self {
            deposit_idx,
            operator_pubkey,
        }
    }

    /// Computes the export leaf for this claim: sha256 over the SSZ encoding.
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
    fn v0_encoding_is_stable() {
        let claim = OperatorClaimUnlockV0::new(1, 2);

        // Two big-endian u32s, deposit index first. Deployed chains hash exactly these bytes.
        let expected = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(encode_to_vec(&claim).unwrap(), expected);
    }

    #[test]
    fn v0_leaf_hash_is_pinned() {
        let claim = OperatorClaimUnlockV0::new(1, 2);

        // Pinned literal rather than a recomputed `hash::raw`, so that a change to the encoding or
        // the hash is caught here instead of silently orphaning every committed leaf.
        assert_eq!(
            hex::encode(claim.compute_hash()),
            "0f585dd518ed0644f3edfd3f7d5012cc9f445c4c9d24e168e694c4d6f36faea6"
        );
    }

    #[test]
    fn v1_ssz_roundtrip() {
        let claim = OperatorClaimUnlockV1::new(1, Buf32::from([2u8; 32]));

        let encoded = claim.as_ssz_bytes();

        // Both fields are fixed-size, so the container is 4 + 32 bytes with no offsets.
        let mut expected = vec![0x01, 0x00, 0x00, 0x00];
        expected.extend_from_slice(&[2u8; 32]);
        assert_eq!(encoded, expected);

        assert_eq!(
            OperatorClaimUnlockV1::from_ssz_bytes(&encoded).unwrap(),
            claim
        );
    }

    #[test]
    fn v1_leaf_hash_is_pinned() {
        let claim = OperatorClaimUnlockV1::new(1, Buf32::from([2u8; 32]));

        assert_eq!(
            hex::encode(claim.compute_hash()),
            "79525990a6761c9f3e4de9cd1a20c81183ecca4f3e1916ffe63c5fd60129ab82"
        );
    }

    #[test]
    fn versions_hash_differently() {
        // Both name the same fulfillment, by an operator whose table index happens to be 2.
        // Nothing should let a v1 leaf pass for the v0 leaf of the same claim.
        let v0 = OperatorClaimUnlockV0::new(1, 2);
        let v1 = OperatorClaimUnlockV1::new(1, Buf32::from([2u8; 32]));

        assert_ne!(v0.compute_hash(), v1.compute_hash());
    }

    proptest! {
        /// The pinned vectors fix one point of each layout; this covers the rest of the input
        /// space, where a field ordering or width mistake would otherwise only show up once a
        /// real claim hit it.
        #[test]
        fn v0_codec_roundtrips_for_any_value(deposit_idx: u32, operator_idx: u32) {
            let claim = OperatorClaimUnlockV0::new(deposit_idx, operator_idx);

            let encoded = encode_to_vec(&claim).unwrap();

            prop_assert_eq!(encoded.len(), 8);
            prop_assert_eq!(&encoded[..4], &deposit_idx.to_be_bytes()[..]);
            prop_assert_eq!(&encoded[4..], &operator_idx.to_be_bytes()[..]);
        }

        #[test]
        fn v1_ssz_roundtrips_for_any_value(deposit_idx: u32, operator_pubkey: [u8; 32]) {
            let claim = OperatorClaimUnlockV1::new(deposit_idx, Buf32::from(operator_pubkey));

            let encoded = claim.as_ssz_bytes();

            prop_assert_eq!(encoded.len(), 36);
            prop_assert_eq!(OperatorClaimUnlockV1::from_ssz_bytes(&encoded).unwrap(), claim);
        }
    }
}
