//! [`AsmManifestMmrDb`] implementation backed by sled.
//!
//! Backed by [`strata_merkle_node_store`]: every MMR node (leaves and internal
//! nodes) is persisted, so an inclusion proof is generated in `O(log n)` by
//! walking the stored sibling path — no replay of the whole MMR from leaf 0.

use anyhow::Result;
use strata_asm_common::AsmManifestHash;
use strata_merkle::{MerkleProofB32, Sha256Hasher};
use strata_merkle_node_store::{MmrNodeStore, NodePos, StoredMmr};

use crate::AsmManifestMmrDb;

/// Decodes a stored 32-byte node value into a hash.
///
/// The store only ever writes 32-byte values, so a wrong length is disk
/// corruption rather than a recoverable condition.
fn decode_node(value: sled::IVec) -> [u8; 32] {
    value
        .as_ref()
        .try_into()
        .expect("mmr node value must be 32 bytes")
}

/// Sled-backed [`MmrNodeStore`] for the manifest-hash MMR.
///
/// One MMR per store, so nodes are keyed directly by [`NodePos::to_key`] with
/// no namespacing.
#[derive(Debug, Clone)]
struct AsmManifestMmrNodeStore {
    nodes: sled::Tree,
}

impl MmrNodeStore for AsmManifestMmrNodeStore {
    type Hash = [u8; 32];
    type Error = sled::Error;

    fn get_node(&self, pos: NodePos) -> Result<Option<[u8; 32]>, sled::Error> {
        Ok(self.nodes.get(pos.to_key())?.map(decode_node))
    }

    fn put_node(&self, pos: NodePos, value: [u8; 32]) -> Result<(), sled::Error> {
        self.nodes.insert(pos.to_key(), value.as_slice())?;
        Ok(())
    }

    fn delete_node(&self, pos: NodePos) -> Result<(), sled::Error> {
        self.nodes.remove(pos.to_key())?;
        Ok(())
    }

    fn commit(
        &self,
        writes: &[(NodePos, [u8; 32])],
        deletes: &[NodePos],
    ) -> Result<(), sled::Error> {
        let mut batch = sled::Batch::default();
        // Apply deletes before writes so a position in both ends up stored, per
        // the `MmrNodeStore::commit` contract.
        for pos in deletes {
            batch.remove(pos.to_key().as_slice());
        }
        for (pos, value) in writes {
            let key = pos.to_key();
            batch.insert(key.as_slice(), value.as_slice());
        }
        self.nodes.apply_batch(batch)
    }
}

/// Sled-backed [`AsmManifestMmrDb`] for manifest hashes.
///
/// Stores every MMR node so inclusion proofs are `O(log n)` and need no leaf
/// replay. The compact peaks are not persisted: proofs are assembled directly
/// from the stored sibling path and verify against the compact-peaks
/// accumulators the rest of the system already holds.
#[derive(Debug, Clone)]
pub struct SledAsmManifestMmrDb {
    inner: AsmManifestMmrNodeStore,
}

impl SledAsmManifestMmrDb {
    /// Opens or creates the MMR node tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            inner: AsmManifestMmrNodeStore {
                nodes: db.open_tree("mmr_nodes")?,
            },
        })
    }

    /// Synchronous variant of [`AsmManifestMmrDb::leaf_count`].
    pub fn leaf_count(&self) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::leaf_count(&self.inner)?)
    }

    /// Synchronous variant of [`AsmManifestMmrDb::put_leaf`].
    ///
    /// The MMR is height-indexed, so the leaf for the L1 block at `height`
    /// lands at leaf index `height`. `height` must be the current end (an
    /// append) or an existing index (an overwrite); a gap past the end is
    /// rejected.
    pub fn put_leaf(&self, height: u64, hash: AsmManifestHash) -> Result<()> {
        StoredMmr::<Sha256Hasher>::put_leaf(&self.inner, height, *hash.as_ref())?;
        Ok(())
    }

    /// Synchronous variant of [`AsmManifestMmrDb::get_leaf`].
    pub fn get_leaf(&self, index: u64) -> Result<Option<AsmManifestHash>> {
        Ok(StoredMmr::<Sha256Hasher>::get_leaf(&self.inner, index)?.map(AsmManifestHash::from))
    }

    /// Synchronous variant of [`AsmManifestMmrDb::generate_proof`].
    ///
    /// `O(log n)`: walks the stored sibling path rather than replaying leaves.
    /// The store yields a generic [`MerkleProof`](strata_merkle::MerkleProof);
    /// it is repacked as a [`MerkleProofB32`] so the store's public API and the
    /// accumulators it verifies against are unchanged.
    pub fn generate_proof(&self, index: u64, at_leaf_count: u64) -> Result<MerkleProofB32> {
        let proof =
            StoredMmr::<Sha256Hasher>::generate_proof_at_size(&self.inner, index, at_leaf_count)?;
        Ok(MerkleProofB32::from_generic(&proof))
    }
}

impl AsmManifestMmrDb for SledAsmManifestMmrDb {
    type Error = anyhow::Error;

    async fn leaf_count(&self) -> Result<u64> {
        self.leaf_count()
    }

    async fn put_leaf(&self, height: u64, hash: AsmManifestHash) -> Result<()> {
        self.put_leaf(height, hash)
    }

    async fn get_leaf(&self, index: u64) -> Result<Option<AsmManifestHash>> {
        self.get_leaf(index)
    }

    async fn generate_proof(&self, index: u64, at_leaf_count: u64) -> Result<MerkleProofB32> {
        self.generate_proof(index, at_leaf_count)
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_common::AsmManifestHash;
    use strata_merkle::{Mmr, Mmr64B32, MmrState, Sha256Hasher};

    use super::*;

    fn test_db() -> sled::Db {
        let dir = tempfile::tempdir().unwrap();
        sled::open(dir.path()).unwrap()
    }

    /// A distinct, non-zero leaf for `seed`. The non-zero marker matters: the
    /// compact-peaks MMR these proofs verify against treats an all-zero hash as
    /// an empty-peak sentinel, so `[0; 32]` is not a representable leaf.
    fn make_leaf(seed: u8) -> AsmManifestHash {
        let mut bytes = [seed; 32];
        bytes[31] = 0xAB;
        AsmManifestHash::from(bytes)
    }

    /// Reference compact-peaks MMR built by replaying the first `size` leaves
    /// of `mmr_db`, matching the accumulators that proofs verify against.
    fn rebuild_compact_mmr(mmr_db: &SledAsmManifestMmrDb, size: u64) -> Mmr64B32 {
        let mut compact = Mmr64B32::new_empty();
        for i in 0..size {
            let leaf = mmr_db.get_leaf(i).unwrap().unwrap();
            Mmr::<Sha256Hasher>::add_leaf(&mut compact, *leaf.as_ref()).unwrap();
        }
        compact
    }

    #[test]
    fn empty_mmr_has_zero_leaves() {
        let db = test_db();
        let mmr = SledAsmManifestMmrDb::open(&db).unwrap();
        assert_eq!(mmr.leaf_count().unwrap(), 0);
    }

    #[test]
    fn put_and_retrieve_leaf() {
        let db = test_db();
        let mmr = SledAsmManifestMmrDb::open(&db).unwrap();
        let leaf = make_leaf(0xaa);

        mmr.put_leaf(0, leaf).unwrap();
        assert_eq!(mmr.leaf_count().unwrap(), 1);

        let retrieved = mmr.get_leaf(0).unwrap().unwrap();
        assert_eq!(retrieved, leaf);
    }

    #[test]
    fn put_multiple_leaves() {
        let db = test_db();
        let mmr = SledAsmManifestMmrDb::open(&db).unwrap();

        for i in 0u8..5 {
            mmr.put_leaf(i as u64, make_leaf(i)).unwrap();
        }

        assert_eq!(mmr.leaf_count().unwrap(), 5);

        for i in 0u8..5 {
            let leaf = mmr.get_leaf(i as u64).unwrap().unwrap();
            assert_eq!(leaf, make_leaf(i));
        }
    }

    #[test]
    fn put_leaf_rejects_gap() {
        let db = test_db();
        let mmr = SledAsmManifestMmrDb::open(&db).unwrap();
        // Leaf index 1 skips index 0, which would leave a hole.
        assert!(mmr.put_leaf(1, make_leaf(0)).is_err());
    }

    #[test]
    fn get_missing_leaf_returns_none() {
        let db = test_db();
        let mmr = SledAsmManifestMmrDb::open(&db).unwrap();
        assert!(mmr.get_leaf(0).unwrap().is_none());
    }

    #[test]
    fn generate_and_verify_proof_single_leaf() {
        let db = test_db();
        let mmr_db = SledAsmManifestMmrDb::open(&db).unwrap();
        let leaf = make_leaf(0x01);
        mmr_db.put_leaf(0, leaf).unwrap();

        let proof = mmr_db.generate_proof(0, 1).unwrap();
        let compact = rebuild_compact_mmr(&mmr_db, 1);
        assert!(compact.verify(&proof, leaf.as_ref()));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let mmr_db = SledAsmManifestMmrDb::open(&db).unwrap();

        for i in 0u8..8 {
            mmr_db.put_leaf(i as u64, make_leaf(i)).unwrap();
        }

        let compact = rebuild_compact_mmr(&mmr_db, 8);
        for i in 0u64..8 {
            let proof = mmr_db
                .generate_proof(i, 8)
                .unwrap_or_else(|e| panic!("proof generation failed for leaf {i}: {e}"));
            assert!(compact.verify(&proof, make_leaf(i as u8).as_ref()));
        }
    }

    #[test]
    fn proof_at_earlier_size_is_valid() {
        let db = test_db();
        let mmr_db = SledAsmManifestMmrDb::open(&db).unwrap();

        // Put 4 leaves, snapshot the compact state.
        for i in 0u8..4 {
            mmr_db.put_leaf(i as u64, make_leaf(i)).unwrap();
        }
        let compact_at_4 = rebuild_compact_mmr(&mmr_db, 4);

        // Put 4 more.
        for i in 4u8..8 {
            mmr_db.put_leaf(i as u64, make_leaf(i)).unwrap();
        }

        // Proof at size 4 should verify against the snapshot.
        let proof = mmr_db.generate_proof(2, 4).unwrap();
        assert!(compact_at_4.verify(&proof, make_leaf(2).as_ref()));
    }
}
