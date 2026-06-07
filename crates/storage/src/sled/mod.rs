//! [Sled](https://docs.rs/sled)-backed implementations of the ASM storage
//! traits.
//!
//! Each store keys its tree by [`L1BlockCommitment`] using a big-endian
//! `[height(4)][blkid(32)]` encoding (see below), so sled's lexicographic
//! ordering matches block-height ordering. Each implementation keeps
//! synchronous inherent methods for the worker, which runs on a sync thread,
//! and delegates to them from the async trait.

use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

mod aux;
mod manifest;
mod manifest_mmr;
mod state;

pub use self::{
    aux::SledAsmAuxDataDb, manifest::SledAsmManifestDb, manifest_mmr::SledAsmManifestMmrDb,
    state::SledAsmStateDb,
};

// ── Key encoding ──────────────────────────────────────────────────────
//
// We use a custom big-endian encoding for block commitment keys instead of
// borsh because borsh serializes integers as little-endian. Big-endian encoding
// ensures that sled's lexicographic key ordering matches block-height ordering,
// which is what lets `prune` use a range scan and `get_latest` use `Tree::last`.

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
///
/// Keys are write-only today — `put` derives them, `get_latest` reads the value
/// and derives the commitment from the state, and `prune` ranges on raw bytes —
/// but this completes the encode/decode pair and is useful for key
/// iteration/debugging.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "completes the encode/decode pair")
)]
pub(crate) fn decode_block_commitment(buf: &[u8]) -> L1BlockCommitment {
    let height = u32::from_be_bytes(buf[0..4].try_into().expect("key is at least 4 bytes"));
    let blkid: [u8; 32] = buf[4..36].try_into().expect("key is at least 36 bytes");
    L1BlockCommitment::new(height, L1BlockId::from(Buf32::from(blkid)))
}

#[cfg(test)]
pub(crate) mod test_util {
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

    /// Creates an isolated sled database backed by a temporary directory.
    ///
    /// The `TempDir` is dropped with the returned `Db`, so callers keep both
    /// alive for the duration of a test.
    pub(crate) fn test_db() -> (sled::Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = sled::open(dir.path()).expect("failed to open sled db");
        (db, dir)
    }

    /// Builds an [`L1BlockCommitment`] at `height` with a `seed`-filled block id.
    pub(crate) fn make_commitment(height: u32, seed: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::new([seed; 32])))
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::make_commitment;

    #[test]
    fn block_commitment_key_roundtrip() {
        let commitment = make_commitment(123_456, 0xab);
        let encoded = super::encode_block_commitment(&commitment);
        let decoded = super::decode_block_commitment(&encoded);
        assert_eq!(commitment, decoded);
    }
}
