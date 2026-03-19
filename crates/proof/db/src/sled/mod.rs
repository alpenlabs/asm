//! [Sled](https://docs.rs/sled)-backed implementation of [`super::ProofDb`],
//! [`super::RemoteProofMappingDb`], and [`super::RemoteProofStatusDb`].
//!
//! All data is stored in a single sled database with separate trees for each
//! concern. Keys use big-endian height encoding so that sled's lexicographic
//! ordering matches block-height ordering.

use std::path::Path;

use strata_asm_proof_types::L1Range;
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

mod proof_db;
mod remote_mapping;
mod remote_status;

pub use self::{remote_mapping::RemoteProofMappingError, remote_status::RemoteProofStatusError};

/// Sled-backed proof database.
///
/// Implements [`super::ProofDb`], [`super::RemoteProofMappingDb`], and
/// [`super::RemoteProofStatusDb`] using five sled trees within a single database.
/// Proof keys are encoded with big-endian heights so that sled's lexicographic
/// ordering matches block-height ordering.
#[derive(Debug, Clone)]
pub struct SledProofDb {
    /// ASM step proofs, keyed by `[start_height‖start_blkid‖end_height‖end_blkid]` (72 bytes).
    pub(crate) asm_proofs: sled::Tree,
    /// Moho recursive proofs, keyed by `[height‖blkid]` (36 bytes).
    pub(crate) moho_proofs: sled::Tree,
    /// Forward mapping: `ProofId` (borsh-encoded) → `RemoteProofId` (raw bytes).
    pub(crate) proof_to_remote: sled::Tree,
    /// Reverse mapping: `RemoteProofId` (raw bytes) → `ProofId` (borsh-encoded).
    pub(crate) remote_to_proof: sled::Tree,
    /// Status tracking: `RemoteProofId` (raw bytes) → `RemoteProofStatus` (borsh-encoded).
    pub(crate) remote_proof_status: sled::Tree,
}

impl SledProofDb {
    /// Opens (or creates) the proof database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        let asm_proofs = db.open_tree("asm_proofs")?;
        let moho_proofs = db.open_tree("moho_proofs")?;
        let proof_to_remote = db.open_tree("proof_to_remote")?;
        let remote_to_proof = db.open_tree("remote_to_proof")?;
        let remote_proof_status = db.open_tree("remote_proof_status")?;
        Ok(Self {
            asm_proofs,
            moho_proofs,
            proof_to_remote,
            remote_to_proof,
            remote_proof_status,
        })
    }
}

// ── Key encoding ──────────────────────────────────────────────────────
//
// We use a custom big-endian encoding for block commitment keys instead of
// borsh/bincode because those serialize integers as little-endian. Big-endian
// encoding ensures that sled's lexicographic key ordering matches block-height
// ordering, which is required for range scans and `last()` queries.

/// Size of an encoded [`L1BlockCommitment`]: 4-byte BE height + 32-byte block id.
const ENCODED_L1_COMMITMENT_SIZE: usize = 4 + 32;

/// Size of an encoded [`L1Range`]: two consecutive encoded commitments.
const ENCODED_L1_RANGE_SIZE: usize = ENCODED_L1_COMMITMENT_SIZE * 2;

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

/// Encodes an ASM proof key as 72 bytes:
/// `[start_commitment(36)][end_commitment(36)]`
pub(crate) fn encode_asm_key(range: &L1Range) -> [u8; ENCODED_L1_RANGE_SIZE] {
    let mut key = [0u8; ENCODED_L1_RANGE_SIZE];
    key[..ENCODED_L1_COMMITMENT_SIZE].copy_from_slice(&encode_block_commitment(&range.start()));
    key[ENCODED_L1_COMMITMENT_SIZE..].copy_from_slice(&encode_block_commitment(&range.end()));
    key
}

/// Decodes a 72-byte ASM proof key back into an [`L1Range`].
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "completes the encode/decode pair; useful for key iteration/debugging"
    )
)]
pub(crate) fn decode_asm_key(key: &[u8; ENCODED_L1_RANGE_SIZE]) -> L1Range {
    let start = decode_block_commitment(&key[..ENCODED_L1_COMMITMENT_SIZE]);
    let end = decode_block_commitment(&key[ENCODED_L1_COMMITMENT_SIZE..]);
    L1Range::new(start, end).expect("decoded range must be valid")
}

/// Alias: encodes a Moho proof key (same as a single block commitment).
pub(crate) fn encode_moho_key(l1ref: &L1BlockCommitment) -> [u8; ENCODED_L1_COMMITMENT_SIZE] {
    encode_block_commitment(l1ref)
}

/// Alias: decodes a Moho proof key (same as a single block commitment).
pub(crate) fn decode_moho_key(key: &[u8]) -> L1BlockCommitment {
    decode_block_commitment(key)
}

#[cfg(test)]
pub(crate) mod test_util {
    use proptest::{collection::vec, prelude::*};
    use strata_asm_proof_types::{AsmProof, L1Range, MohoProof};
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use zkaleido::{
        Proof, ProofMetadata, ProofReceipt, ProofReceiptWithMetadata, PublicValues, ZkVm,
    };

    use super::SledProofDb;

    /// Creates an isolated [`SledProofDb`] backed by a temporary directory.
    pub(crate) fn temp_db() -> (SledProofDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = SledProofDb::open(dir.path()).expect("failed to open sled db");
        (db, dir)
    }

    /// Generates an arbitrary L1BlockCommitment.
    /// Heights must be < 500_000_000 (bitcoin LOCK_TIME_THRESHOLD).
    pub(crate) fn arb_l1_block_commitment() -> impl Strategy<Value = L1BlockCommitment> {
        (0u32..500_000_000u32, any::<[u8; 32]>())
            .prop_map(|(h, blkid)| L1BlockCommitment::new(h, L1BlockId::from(Buf32::from(blkid))))
    }

    /// Generates an arbitrary L1Range (end height >= start height).
    pub(crate) fn arb_l1_range() -> impl Strategy<Value = L1Range> {
        (arb_l1_block_commitment(), arb_l1_block_commitment())
            .prop_filter_map("end height must be >= start height", |(a, b)| {
                L1Range::new(a, b)
            })
    }

    pub(crate) fn arb_proof_receipt_with_metadata()
    -> impl Strategy<Value = ProofReceiptWithMetadata> {
        (vec(any::<u8>(), 0..512), vec(any::<u8>(), 0..512)).prop_map(|(proof_bytes, pv_bytes)| {
            let receipt = ProofReceipt::new(Proof::new(proof_bytes), PublicValues::new(pv_bytes));
            let metadata = ProofMetadata::new(ZkVm::Native, "test");
            ProofReceiptWithMetadata::new(receipt, metadata)
        })
    }

    pub(crate) fn arb_asm_proof() -> impl Strategy<Value = AsmProof> {
        arb_proof_receipt_with_metadata().prop_map(AsmProof)
    }

    pub(crate) fn arb_moho_proof() -> impl Strategy<Value = MohoProof> {
        arb_proof_receipt_with_metadata().prop_map(MohoProof)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::test_util::{arb_l1_block_commitment, arb_l1_range};

    proptest! {
        #[test]
        fn block_commitment_key_roundtrip(commitment in arb_l1_block_commitment()) {
            let encoded = super::encode_block_commitment(&commitment);
            let decoded = super::decode_block_commitment(&encoded);
            prop_assert_eq!(commitment, decoded);
        }

        #[test]
        fn asm_key_roundtrip(range in arb_l1_range()) {
            let encoded = super::encode_asm_key(&range);
            let decoded = super::decode_asm_key(&encoded);
            prop_assert_eq!(range, decoded);
        }

        #[test]
        fn moho_key_roundtrip(commitment in arb_l1_block_commitment()) {
            let encoded = super::encode_moho_key(&commitment);
            let decoded = super::decode_moho_key(&encoded);
            prop_assert_eq!(commitment, decoded);
        }
    }
}
