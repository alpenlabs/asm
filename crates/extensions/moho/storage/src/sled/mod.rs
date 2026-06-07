//! [Sled](https://docs.rs/sled)-backed implementation of [`super::MohoStateDb`].
//!
//! State is stored in a single sled tree. Keys use big-endian height encoding so
//! that sled's lexicographic ordering matches block-height ordering, which is
//! required for the range scans `prune` relies on.

use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

mod export_entries;
mod moho_state;

pub use self::{export_entries::SledExportEntriesDb, moho_state::SledMohoStateDb};

// ── Key encoding ──────────────────────────────────────────────────────
//
// We use a custom big-endian encoding for block commitment keys instead of
// borsh/bincode because those serialize integers as little-endian. Big-endian
// encoding ensures that sled's lexicographic key ordering matches block-height
// ordering, which is required for range scans.

/// Size of an encoded [`L1BlockCommitment`]: 4-byte BE height + 32-byte block id.
const ENCODED_L1_COMMITMENT_SIZE: usize = 4 + 32;

/// Encodes an [`L1BlockCommitment`] as 36 bytes: `[height_be(4)][blkid(32)]`.
pub(crate) fn encode_block_commitment(
    commitment: &L1BlockCommitment,
) -> [u8; ENCODED_L1_COMMITMENT_SIZE] {
    let mut buf = [0u8; ENCODED_L1_COMMITMENT_SIZE];
    buf[0..4].copy_from_slice(&commitment.height().to_be_bytes());
    buf[4..36].copy_from_slice(commitment.blkid().as_ref());
    buf
}

/// Decodes a 36-byte buffer back into an [`L1BlockCommitment`].
pub(crate) fn decode_block_commitment(buf: &[u8]) -> L1BlockCommitment {
    let height = u32::from_be_bytes(buf[0..4].try_into().expect("key is at least 4 bytes"));
    let blkid: [u8; 32] = buf[4..36].try_into().expect("key is at least 36 bytes");
    L1BlockCommitment::new(height, L1BlockId::from(Buf32::from(blkid)))
}

/// Alias: encodes a Moho key (same as a single block commitment).
pub(crate) fn encode_moho_key(l1ref: &L1BlockCommitment) -> [u8; ENCODED_L1_COMMITMENT_SIZE] {
    encode_block_commitment(l1ref)
}

/// Alias: decodes a Moho key (same as a single block commitment).
pub(crate) fn decode_moho_key(key: &[u8]) -> L1BlockCommitment {
    decode_block_commitment(key)
}

#[cfg(test)]
pub(crate) mod test_util {
    use proptest::prelude::*;
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

    /// Generates an arbitrary L1BlockCommitment.
    /// Heights must be < 500_000_000 (bitcoin LOCK_TIME_THRESHOLD).
    pub(crate) fn arb_l1_block_commitment() -> impl Strategy<Value = L1BlockCommitment> {
        (0u32..500_000_000u32, any::<[u8; 32]>())
            .prop_map(|(h, blkid)| L1BlockCommitment::new(h, L1BlockId::from(Buf32::from(blkid))))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::test_util::arb_l1_block_commitment;

    proptest! {
        #[test]
        fn block_commitment_key_roundtrip(commitment in arb_l1_block_commitment()) {
            let encoded = super::encode_block_commitment(&commitment);
            let decoded = super::decode_block_commitment(&encoded);
            prop_assert_eq!(commitment, decoded);
        }

        #[test]
        fn moho_key_roundtrip(commitment in arb_l1_block_commitment()) {
            let encoded = super::encode_moho_key(&commitment);
            let decoded = super::decode_moho_key(&encoded);
            prop_assert_eq!(commitment, decoded);
        }
    }
}
