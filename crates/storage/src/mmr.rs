//! Sled-backed Merkle Mountain Range for manifest hashes.
//!
//! Backed by [`strata_merkle_node_store`]: every MMR node (leaves and internal
//! nodes) is persisted, so an inclusion proof is generated in `O(log n)` by
//! walking the stored sibling path — no replay of the whole MMR from leaf 0.

use anyhow::Result;
use strata_identifiers::Buf32;
use strata_merkle::{MerkleProofB32, Sha256Hasher};
use strata_merkle_node_store::{MmrNodeStore, NodePos, StoredMmr};

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
struct ManifestNodes {
    nodes: sled::Tree,
}

impl MmrNodeStore for ManifestNodes {
    type Hash = [u8; 32];
    type Error = sled::Error;

    fn get_node(&self, pos: NodePos) -> Result<Option<[u8; 32]>, sled::Error> {
        Ok(self.nodes.get(pos.to_key())?.map(decode_node))
    }

    fn put_node(&self, pos: NodePos, value: [u8; 32]) -> Result<(), sled::Error> {
        self.nodes.insert(pos.to_key(), value.as_slice())?;
        Ok(())
    }

    fn commit(&self, writes: &[(NodePos, [u8; 32])]) -> Result<(), sled::Error> {
        let mut batch = sled::Batch::default();
        for (pos, value) in writes {
            let key = pos.to_key();
            batch.insert(key.as_slice(), value.as_slice());
        }
        self.nodes.apply_batch(batch)
    }
}

/// Sled-backed MMR for manifest hashes.
///
/// Stores every MMR node so inclusion proofs are `O(log n)` and need no leaf
/// replay. The compact peaks are not persisted: proofs are assembled directly
/// from the stored sibling path and verify against the compact-peaks
/// accumulators the rest of the system already holds.
#[derive(Debug, Clone)]
pub struct MmrDb {
    inner: ManifestNodes,
}

impl MmrDb {
    /// Opens or creates the MMR node tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            inner: ManifestNodes {
                nodes: db.open_tree("mmr_nodes")?,
            },
        })
    }

    /// Returns the current leaf count.
    pub fn leaf_count(&self) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::leaf_count(&self.inner)?)
    }

    /// Appends a manifest hash as a new leaf. Returns the leaf index.
    pub fn append_leaf(&self, hash: Buf32) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::append_leaf(&self.inner, hash.0)?)
    }

    /// Retrieves a manifest hash by its leaf index.
    pub fn get_leaf(&self, index: u64) -> Result<Option<Buf32>> {
        Ok(StoredMmr::<Sha256Hasher>::get_leaf(&self.inner, index)?.map(Buf32::new))
    }

    /// Generates an MMR inclusion proof for the leaf at `index` against an MMR
    /// of exactly `at_leaf_count` leaves.
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

#[cfg(test)]
mod tests {
    use strata_identifiers::Buf32;
    use strata_merkle::{Mmr, Mmr64B32, MmrState, Sha256Hasher};

    use super::*;

    fn test_db() -> sled::Db {
        let dir = tempfile::tempdir().unwrap();
        sled::open(dir.path()).unwrap()
    }

    /// A distinct, non-zero leaf for `seed`. The non-zero marker matters: the
    /// compact-peaks MMR these proofs verify against treats an all-zero hash as
    /// an empty-peak sentinel, so `[0; 32]` is not a representable leaf.
    fn make_leaf(seed: u8) -> Buf32 {
        let mut bytes = [seed; 32];
        bytes[31] = 0xAB;
        Buf32::new(bytes)
    }

    /// Reference compact-peaks MMR built by replaying the first `size` leaves
    /// of `mmr_db`, matching the accumulators that proofs verify against.
    fn rebuild_compact_mmr(mmr_db: &MmrDb, size: u64) -> Mmr64B32 {
        let mut compact = Mmr64B32::new_empty();
        for i in 0..size {
            let leaf = mmr_db.get_leaf(i).unwrap().unwrap();
            Mmr::<Sha256Hasher>::add_leaf(&mut compact, leaf.0).unwrap();
        }
        compact
    }

    #[test]
    fn empty_mmr_has_zero_leaves() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();
        assert_eq!(mmr.leaf_count().unwrap(), 0);
    }

    #[test]
    fn append_and_retrieve_leaf() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();
        let leaf = make_leaf(0xaa);

        let idx = mmr.append_leaf(leaf).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(mmr.leaf_count().unwrap(), 1);

        let retrieved = mmr.get_leaf(0).unwrap().unwrap();
        assert_eq!(retrieved, leaf);
    }

    #[test]
    fn append_multiple_leaves() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();

        for i in 0u8..5 {
            let idx = mmr.append_leaf(make_leaf(i)).unwrap();
            assert_eq!(idx, i as u64);
        }

        assert_eq!(mmr.leaf_count().unwrap(), 5);

        for i in 0u8..5 {
            let leaf = mmr.get_leaf(i as u64).unwrap().unwrap();
            assert_eq!(leaf, make_leaf(i));
        }
    }

    #[test]
    fn get_missing_leaf_returns_none() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();
        assert!(mmr.get_leaf(0).unwrap().is_none());
    }

    #[test]
    fn generate_and_verify_proof_single_leaf() {
        let db = test_db();
        let mmr_db = MmrDb::open(&db).unwrap();
        let leaf = make_leaf(0x01);
        mmr_db.append_leaf(leaf).unwrap();

        let proof = mmr_db.generate_proof(0, 1).unwrap();
        let compact = rebuild_compact_mmr(&mmr_db, 1);
        assert!(compact.verify(&proof, &leaf.0));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let mmr_db = MmrDb::open(&db).unwrap();

        for i in 0u8..8 {
            mmr_db.append_leaf(make_leaf(i)).unwrap();
        }

        let compact = rebuild_compact_mmr(&mmr_db, 8);
        for i in 0u64..8 {
            let proof = mmr_db
                .generate_proof(i, 8)
                .unwrap_or_else(|e| panic!("proof generation failed for leaf {i}: {e}"));
            assert!(compact.verify(&proof, &make_leaf(i as u8).0));
        }
    }

    #[test]
    fn proof_at_earlier_size_is_valid() {
        let db = test_db();
        let mmr_db = MmrDb::open(&db).unwrap();

        // Append 4 leaves, snapshot the compact state.
        for i in 0u8..4 {
            mmr_db.append_leaf(make_leaf(i)).unwrap();
        }
        let compact_at_4 = rebuild_compact_mmr(&mmr_db, 4);

        // Append 4 more.
        for i in 4u8..8 {
            mmr_db.append_leaf(make_leaf(i)).unwrap();
        }

        // Proof at size 4 should verify against the snapshot.
        let proof = mmr_db.generate_proof(2, 4).unwrap();
        assert!(compact_at_4.verify(&proof, &make_leaf(2).0));
    }
}
