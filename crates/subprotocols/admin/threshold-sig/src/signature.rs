//! Signature types submitted by administration signers.

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use ssz::DecodeError;
use ssz_primitives::FixedBytes;

use crate::{
    errors::ThresholdSignatureError,
    ssz_bridge::{SszContainer, impl_ssz_via_container},
    ssz_generated::ssz::threshold::{IndexedSignatureSsz, SignatureSetSsz},
};

/// Length of a recoverable ECDSA signature: a header byte plus `r` and `s`.
const SIGNATURE_LEN: usize = 65;

/// An ECDSA signature together with the index of the signer that produced it.
///
/// The signature is in recoverable format (65 bytes): `header || r || s`.
///
/// # Hardware wallet compatibility
///
/// The header byte comes in two flavours:
///
/// 1. A raw recovery ID (0-3), which some signing libraries emit directly.
/// 2. BIP-137 form (27-42), which Bitcoin message signing on hardware wallets emits. 27-30 is
///    uncompressed P2PKH, 31-34 compressed P2PKH (the common Ledger and Trezor case), 35-38 SegWit
///    P2SH-P2WPKH, and 39-42 native SegWit P2WPKH.
///
/// Verification normalizes both to a raw recovery ID.
///
/// A signer supplies its own index, its position in [`ThresholdConfig::keys`]. Verification
/// uses that index to look up the expected key and compares it against the key recovered
/// from the signature, so a wrong index fails rather than silently matching another signer.
///
/// [`ThresholdConfig::keys`]: crate::ThresholdConfig::keys
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct IndexedSignature {
    /// Index of the signer in the [`ThresholdConfig`](crate::ThresholdConfig) key list.
    index: u8,
    /// 65-byte recoverable ECDSA signature (`header || r || s`).
    signature: [u8; SIGNATURE_LEN],
}

impl IndexedSignature {
    /// Creates a new indexed signature.
    pub fn new(index: u8, signature: [u8; SIGNATURE_LEN]) -> Self {
        Self { index, signature }
    }

    /// Returns the signer index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Returns the header byte, which carries the recovery ID in either supported form.
    pub fn recovery_id(&self) -> u8 {
        self.signature[0]
    }

    /// Returns the `r` component.
    pub fn r(&self) -> &[u8; 32] {
        self.signature[1..33]
            .try_into()
            .expect("signature[1..33] is 32 bytes")
    }

    /// Returns the `s` component.
    pub fn s(&self) -> &[u8; 32] {
        self.signature[33..65]
            .try_into()
            .expect("signature[33..65] is 32 bytes")
    }

    /// Returns the compact signature (`r || s`), without the header byte.
    pub fn compact(&self) -> [u8; 64] {
        let mut compact = [0u8; 64];
        compact.copy_from_slice(&self.signature[1..65]);
        compact
    }
}

impl SszContainer for IndexedSignature {
    type Container = IndexedSignatureSsz;

    fn to_container(&self) -> Self::Container {
        IndexedSignatureSsz {
            index: self.index,
            signature: FixedBytes(self.signature),
        }
    }

    fn from_container(container: Self::Container) -> Result<Self, DecodeError> {
        Ok(Self::new(container.index, container.signature.0))
    }
}

impl_ssz_via_container!(IndexedSignature);

/// A set of indexed ECDSA signatures offered against a threshold configuration.
///
/// The set is guaranteed to hold at most one signature per signer index, so counting its
/// members is the same as counting distinct signers.
#[derive(Debug, Clone, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct SignatureSet {
    /// Signatures, with no repeated index.
    signatures: Vec<IndexedSignature>,
}

impl SignatureSet {
    /// Creates a signature set, rejecting a repeated signer index.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdSignatureError::DuplicateSignerIndex`] if an index appears twice.
    /// Without the check one signer could be counted several times towards the threshold.
    pub fn new(signatures: Vec<IndexedSignature>) -> Result<Self, ThresholdSignatureError> {
        let mut seen = HashSet::new();
        for sig in &signatures {
            if !seen.insert(sig.index) {
                return Err(ThresholdSignatureError::DuplicateSignerIndex(sig.index));
            }
        }

        Ok(Self { signatures })
    }

    /// Creates an empty signature set.
    pub fn empty() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Returns the signatures.
    pub fn signatures(&self) -> &[IndexedSignature] {
        &self.signatures
    }

    /// Returns the number of signatures.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Returns whether the set holds no signatures.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Iterates over the signer indices.
    pub fn indices(&self) -> impl Iterator<Item = u8> + '_ {
        self.signatures.iter().map(|s| s.index)
    }

    /// Consumes the set and returns the signatures.
    pub fn into_inner(self) -> Vec<IndexedSignature> {
        self.signatures
    }
}

impl SszContainer for SignatureSet {
    type Container = SignatureSetSsz;

    fn to_container(&self) -> Self::Container {
        // Cannot fail: a set holds at most one signature per signer index, and there are at
        // most `MAX_SIGNERS` of those.
        let signatures = self
            .signatures
            .iter()
            .map(SszContainer::to_container)
            .collect::<Vec<_>>()
            .try_into()
            .expect("set is within MAX_SIGNERS");

        SignatureSetSsz { signatures }
    }

    fn from_container(container: Self::Container) -> Result<Self, DecodeError> {
        let signatures = container
            .signatures
            .iter()
            .cloned()
            .map(IndexedSignature::from_container)
            .collect::<Result<Vec<_>, _>>()?;

        // Re-applies the duplicate-free invariant, so a decoded set cannot over-count a
        // signer towards the threshold.
        Self::new(signatures).map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl_ssz_via_container!(SignatureSet);

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};

    use super::*;

    fn make_sig(index: u8) -> IndexedSignature {
        let mut signature = [0u8; SIGNATURE_LEN];
        signature[0] = 27; // BIP-137 header
        signature[1] = index; // stashed in r so signatures are distinguishable
        IndexedSignature::new(index, signature)
    }

    #[test]
    fn new_preserves_order() {
        let set = SignatureSet::new(vec![make_sig(2), make_sig(0), make_sig(1)]).unwrap();

        assert_eq!(set.indices().collect::<Vec<_>>(), vec![2, 0, 1]);
    }

    #[test]
    fn new_rejects_a_duplicate_index() {
        assert_eq!(
            SignatureSet::new(vec![make_sig(1), make_sig(1)]),
            Err(ThresholdSignatureError::DuplicateSignerIndex(1))
        );
    }

    #[test]
    fn borsh_roundtrips() {
        let set = SignatureSet::new(vec![make_sig(0), make_sig(2), make_sig(5)]).unwrap();
        let encoded = borsh::to_vec(&set).unwrap();

        assert_eq!(borsh::from_slice::<SignatureSet>(&encoded).unwrap(), set);
    }

    #[test]
    fn indexed_signature_exposes_its_components() {
        let mut signature = [0u8; SIGNATURE_LEN];
        signature[0] = 27;
        signature[1..33].copy_from_slice(&[0xAA; 32]);
        signature[33..65].copy_from_slice(&[0xBB; 32]);

        let sig = IndexedSignature::new(5, signature);

        assert_eq!(sig.index(), 5);
        assert_eq!(sig.recovery_id(), 27);
        assert_eq!(sig.r(), &[0xAA; 32]);
        assert_eq!(sig.s(), &[0xBB; 32]);
        assert_eq!(sig.compact()[..32], [0xAA; 32]);
        assert_eq!(sig.compact()[32..], [0xBB; 32]);
    }

    #[test]
    fn indexed_signature_ssz_byte_layout() {
        let mut signature = [0u8; SIGNATURE_LEN];
        signature[0] = 1;
        signature[1..33].copy_from_slice(&[0xCC; 32]);
        signature[33..65].copy_from_slice(&[0xDD; 32]);
        let sig = IndexedSignature::new(3, signature);

        let mut expected = vec![3];
        expected.extend_from_slice(&signature);

        assert_eq!(sig.as_ssz_bytes(), expected);
        assert_eq!(expected.len(), 66);
        assert_eq!(IndexedSignature::from_ssz_bytes(&expected).unwrap(), sig);
    }

    #[test]
    fn indexed_signature_ssz_rejects_a_wrong_length() {
        assert!(IndexedSignature::from_ssz_bytes(&[0u8; 65]).is_err());
        assert!(IndexedSignature::from_ssz_bytes(&[0u8; 67]).is_err());
    }

    #[test]
    fn signature_set_ssz_byte_layout() {
        let sigs = vec![make_sig(0), make_sig(3)];
        let set = SignatureSet::new(sigs.clone()).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&4u32.to_le_bytes()); // offset to signatures
        for sig in &sigs {
            expected.extend_from_slice(&sig.as_ssz_bytes());
        }

        assert_eq!(set.as_ssz_bytes(), expected);
        assert_eq!(set.ssz_bytes_len(), expected.len());
        assert_eq!(SignatureSet::from_ssz_bytes(&expected).unwrap(), set);
    }

    #[test]
    fn empty_signature_set_encodes_to_the_offset_alone() {
        let encoded = SignatureSet::empty().as_ssz_bytes();

        assert_eq!(encoded, 4u32.to_le_bytes());
        assert_eq!(
            SignatureSet::from_ssz_bytes(&encoded).unwrap(),
            SignatureSet::empty()
        );
    }

    #[test]
    fn signature_set_ssz_rejects_a_duplicate_index() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&make_sig(1).as_ssz_bytes());
        bytes.extend_from_slice(&make_sig(1).as_ssz_bytes());

        assert!(SignatureSet::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn signature_set_ssz_rejects_a_truncated_signature() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&make_sig(1).as_ssz_bytes()[..65]);

        assert!(SignatureSet::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn signature_set_ssz_rejects_a_misplaced_offset() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes()); // should be 4
        bytes.extend_from_slice(&make_sig(1).as_ssz_bytes());

        assert!(SignatureSet::from_ssz_bytes(&bytes).is_err());
    }
}
