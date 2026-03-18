//! [Sled](https://docs.rs/sled)-backed implementation of [`super::ProofDb`],
//! [`super::RemoteProofMappingDb`], and [`super::RemoteProofStatusDb`].
//!
//! All data is stored in a single sled database with separate trees for each
//! concern. Keys use big-endian height encoding so that sled's lexicographic
//! ordering matches block-height ordering.

use std::path::Path;

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

/// Encodes an ASM proof key as 72 bytes:
/// `[start_height_be(4)][start_blkid(32)][end_height_be(4)][end_blkid(32)]`
pub(crate) fn encode_asm_key(range: &strata_asm_proof_types::L1Range) -> [u8; 72] {
    let mut key = [0u8; 72];
    key[0..4].copy_from_slice(&range.start().height().to_be_bytes());
    key[4..36].copy_from_slice(range.start().blkid().as_ref());
    key[36..40].copy_from_slice(&range.end().height().to_be_bytes());
    key[40..72].copy_from_slice(range.end().blkid().as_ref());
    key
}

/// Encodes a Moho proof key as 36 bytes:
/// `[height_be(4)][blkid(32)]`
pub(crate) fn encode_moho_key(l1ref: &L1BlockCommitment) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[0..4].copy_from_slice(&l1ref.height().to_be_bytes());
    key[4..36].copy_from_slice(l1ref.blkid().as_ref());
    key
}

/// Decodes a Moho proof key back into an [`L1BlockCommitment`].
pub(crate) fn decode_moho_key(key: &[u8]) -> L1BlockCommitment {
    let height = u32::from_be_bytes(key[0..4].try_into().expect("key is at least 4 bytes"));
    let blkid: [u8; 32] = key[4..36].try_into().expect("key is at least 36 bytes");
    L1BlockCommitment::new(height, L1BlockId::from(Buf32::from(blkid)))
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
