//! Sled-backed index of per-container export entries.
//!
//! `MohoState` keeps only each container's compact MMR (peaks), so the
//! original 32-byte leaves can't be recovered from it. We mirror them here so
//! the RPC can rebuild inclusion proofs on demand.
//!
//! Backed by [`strata_merkle_node_store`]: every MMR node is persisted, so a
//! proof is `O(log n)` with no leaf replay. Containers share one node tree,
//! namespaced by `container_id`. Alongside the nodes we keep two small indexes
//! the MMR itself does not carry: the insertion height per leaf, and a reverse
//! `hash → index` map for lookups and append idempotency.

use anyhow::{Context, Result};
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

/// One container's view onto the shared node tree, namespacing every key with
/// `container_id` so each container is an independent MMR.
#[derive(Debug)]
struct ContainerNodes<'a> {
    tree: &'a sled::Tree,
    container_id: u8,
}

impl ContainerNodes<'_> {
    /// `container_id || NodePos::to_key()`.
    fn key(&self, pos: NodePos) -> [u8; 10] {
        let mut key = [0u8; 10];
        key[0] = self.container_id;
        key[1..].copy_from_slice(&pos.to_key());
        key
    }
}

impl MmrNodeStore for ContainerNodes<'_> {
    type Hash = [u8; 32];
    type Error = sled::Error;

    fn get_node(&self, pos: NodePos) -> Result<Option<[u8; 32]>, sled::Error> {
        Ok(self.tree.get(self.key(pos))?.map(decode_node))
    }

    fn put_node(&self, pos: NodePos, value: [u8; 32]) -> Result<(), sled::Error> {
        self.tree.insert(self.key(pos), value.as_slice())?;
        Ok(())
    }

    fn delete_node(&self, pos: NodePos) -> Result<(), sled::Error> {
        self.tree.remove(self.key(pos))?;
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
            batch.remove(self.key(*pos).as_slice());
        }
        for (pos, value) in writes {
            let key = self.key(*pos);
            batch.insert(key.as_slice(), value.as_slice());
        }
        self.tree.apply_batch(batch)
    }
}

/// Per-container export-entry store: a namespaced MMR node tree plus a
/// `(container_id, index) → height` map and a reverse
/// `(container_id, hash) → index` map.
#[derive(Debug, Clone)]
pub struct ExportEntriesDb {
    nodes: sled::Tree,
    heights: sled::Tree,
    index_by_hash: sled::Tree,
}

impl ExportEntriesDb {
    /// Opens or creates the export entries trees in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            nodes: db.open_tree("export_entry_nodes")?,
            heights: db.open_tree("export_entry_heights")?,
            index_by_hash: db.open_tree("export_entries_by_hash")?,
        })
    }

    /// The MMR view for `container_id`.
    fn container(&self, container_id: u8) -> ContainerNodes<'_> {
        ContainerNodes {
            tree: &self.nodes,
            container_id,
        }
    }

    /// Reads the insertion height stored for `(container_id, mmr_index)`.
    fn height_at(&self, container_id: u8, mmr_index: u64) -> Result<Option<u32>> {
        match self.heights.get(encode_key(container_id, mmr_index))? {
            Some(bytes) => Ok(Some(u32::from_be_bytes(
                bytes.as_ref().try_into().context("invalid height bytes")?,
            ))),
            None => Ok(None),
        }
    }

    /// Appends an entry for `container_id` and returns its `mmr_index`.
    ///
    /// Idempotent: a duplicate `(container_id, entry)` returns the original
    /// index unchanged, so block replays after restart are a no-op. Assumes
    /// `(container_id, entry_hash)` is unique within a correct chain.
    pub fn append(&self, container_id: u8, height: u32, entry: [u8; 32]) -> Result<u64> {
        let hash_key = encode_hash_key(container_id, &entry);
        if let Some(existing) = self.index_by_hash.get(hash_key)? {
            return decode_idx(existing.as_ref());
        }

        // Append the leaf (and its recomputed ancestors) to the node store,
        // then record its height and reverse index. The reverse index is the
        // dedup gate, so it is written last: a crash before it leaves the
        // block uncommitted and the worker reprocesses it on restart.
        let index = StoredMmr::<Sha256Hasher>::append_leaf(&self.container(container_id), entry)?;
        self.heights
            .insert(encode_key(container_id, index), &height.to_be_bytes())?;
        self.index_by_hash.insert(hash_key, &index.to_be_bytes())?;
        Ok(index)
    }

    /// Returns the number of entries currently stored for `container_id`.
    pub fn num_entries(&self, container_id: u8) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::leaf_count(
            &self.container(container_id),
        )?)
    }

    /// Reverse lookup: returns `(mmr_index, insertion_height)` for `hash`
    /// under `container_id`, or `None` if absent.
    pub fn find_index(&self, container_id: u8, hash: &[u8; 32]) -> Result<Option<(u64, u32)>> {
        let hash_key = encode_hash_key(container_id, hash);
        let Some(idx_bytes) = self.index_by_hash.get(hash_key)? else {
            return Ok(None);
        };
        let mmr_index = decode_idx(idx_bytes.as_ref())?;
        let height = self
            .height_at(container_id, mmr_index)?
            .context("secondary index points at missing primary entry")?;
        Ok(Some((mmr_index, height)))
    }

    /// Fetches `(insertion_height, entry_hash)` at `(container_id, mmr_index)`.
    pub fn get(&self, container_id: u8, mmr_index: u64) -> Result<Option<(u32, [u8; 32])>> {
        let Some(hash) =
            StoredMmr::<Sha256Hasher>::get_leaf(&self.container(container_id), mmr_index)?
        else {
            return Ok(None);
        };
        let height = self
            .height_at(container_id, mmr_index)?
            .context("leaf present but its height is missing")?;
        Ok(Some((height, hash)))
    }

    /// Generates an inclusion proof for `mmr_index` against the container's
    /// MMR at size `at_leaf_count`.
    ///
    /// `O(log n)`: walks the stored sibling path rather than replaying leaves.
    /// The store yields a generic [`MerkleProof`](strata_merkle::MerkleProof);
    /// it is repacked as a [`MerkleProofB32`] so the store's public API and the
    /// accumulators it verifies against are unchanged.
    pub fn generate_proof(
        &self,
        container_id: u8,
        mmr_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProofB32> {
        let proof = StoredMmr::<Sha256Hasher>::generate_proof_at_size(
            &self.container(container_id),
            mmr_index,
            at_leaf_count,
        )?;
        Ok(MerkleProofB32::from_generic(&proof))
    }
}

fn encode_key(container_id: u8, mmr_index: u64) -> [u8; 9] {
    let mut key = [0u8; 9];
    key[0] = container_id;
    key[1..].copy_from_slice(&mmr_index.to_be_bytes());
    key
}

fn encode_hash_key(container_id: u8, hash: &[u8; 32]) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = container_id;
    key[1..].copy_from_slice(hash);
    key
}

fn decode_idx(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().context("invalid mmr_index bytes")?,
    ))
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};
    use strata_merkle::{Mmr, Mmr64B32, MmrState, Sha256Hasher};

    use super::*;

    fn test_db() -> sled::Db {
        let dir = tempfile::tempdir().unwrap();
        sled::open(dir.path()).unwrap()
    }

    /// A distinct, non-zero entry hash for `seed`. The non-zero marker matters:
    /// the compact-peaks MMR these proofs verify against treats an all-zero
    /// hash as an empty-peak sentinel, so `[0; 32]` is not a representable leaf.
    fn hash(seed: u8) -> [u8; 32] {
        let mut bytes = [seed; 32];
        bytes[31] = 0xAB;
        bytes
    }

    #[test]
    fn append_assigns_monotonic_indices_per_container() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        assert_eq!(store.append(1, 10, hash(0xa1)).unwrap(), 0);
        assert_eq!(store.append(1, 11, hash(0xa2)).unwrap(), 1);
        assert_eq!(store.append(2, 11, hash(0xb1)).unwrap(), 0);
        assert_eq!(store.append(1, 12, hash(0xa3)).unwrap(), 2);
        assert_eq!(store.append(2, 12, hash(0xb2)).unwrap(), 1);
    }

    #[test]
    fn num_entries_matches_appends() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        assert_eq!(store.num_entries(7).unwrap(), 0);
        for i in 0..5u8 {
            store.append(7, 100 + i as u32, hash(i)).unwrap();
        }
        assert_eq!(store.num_entries(7).unwrap(), 5);
        assert_eq!(store.num_entries(8).unwrap(), 0);
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        store.append(1, 42, hash(0xaa)).unwrap();

        assert!(store.get(1, 1).unwrap().is_none());
        assert!(store.get(2, 0).unwrap().is_none());
    }

    #[test]
    fn get_returns_height_and_hash() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        store.append(3, 999, hash(0xcc)).unwrap();

        let (height, got) = store.get(3, 0).unwrap().unwrap();
        assert_eq!(height, 999);
        assert_eq!(got, hash(0xcc));
    }

    #[test]
    fn find_index_returns_match_with_height() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, hash(0xa0)).unwrap();
        store.append(1, 11, hash(0xa1)).unwrap();
        store.append(1, 12, hash(0xa2)).unwrap();
        store.append(2, 10, hash(0xa1)).unwrap(); // same hash, different container

        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 11)));
        assert_eq!(store.find_index(2, &hash(0xa1)).unwrap(), Some((0, 10)));
        assert_eq!(store.find_index(1, &hash(0xff)).unwrap(), None);
        assert_eq!(store.find_index(3, &hash(0xa1)).unwrap(), None);
    }

    #[test]
    fn append_is_idempotent_on_duplicate_hash() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        let idx0 = store.append(1, 10, hash(0xa0)).unwrap();
        let idx1 = store.append(1, 11, hash(0xa1)).unwrap();

        // Replay the same entry — should return the original index,
        // not bump num_entries, and not overwrite the original (height, hash).
        let replay_idx = store.append(1, 999, hash(0xa0)).unwrap();
        assert_eq!(replay_idx, idx0);
        assert_eq!(store.num_entries(1).unwrap(), 2);
        assert_eq!(store.get(1, idx0).unwrap().unwrap(), (10, hash(0xa0)));
        assert_eq!(store.get(1, idx1).unwrap().unwrap(), (11, hash(0xa1)));
    }

    /// Reference compact-peaks MMR built by replaying the first `size` leaves
    /// of `container_id`, matching the accumulators that proofs verify against.
    fn rebuild_compact_mmr(store: &ExportEntriesDb, container_id: u8, size: u64) -> Mmr64B32 {
        let mut compact = Mmr64B32::new_empty();
        for i in 0..size {
            let (_h, hash) = store.get(container_id, i).unwrap().unwrap();
            Mmr::<Sha256Hasher>::add_leaf(&mut compact, hash).unwrap();
        }
        compact
    }

    #[test]
    fn generate_and_verify_proof_single_leaf() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        let h = hash(0x01);
        store.append(4, 100, h).unwrap();

        let proof = store.generate_proof(4, 0, 1).unwrap();
        let compact = rebuild_compact_mmr(&store, 4, 1);
        assert!(compact.verify(&proof, &h));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        for i in 0u8..8 {
            store.append(5, 1000 + i as u32, hash(i)).unwrap();
        }

        let compact = rebuild_compact_mmr(&store, 5, 8);
        for i in 0u64..8 {
            let proof = store
                .generate_proof(5, i, 8)
                .unwrap_or_else(|e| panic!("proof generation failed for leaf {i}: {e}"));
            assert!(compact.verify(&proof, &hash(i as u8)));
        }
    }

    #[test]
    fn proof_at_earlier_size_is_valid() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        for i in 0u8..4 {
            store.append(6, 100 + i as u32, hash(i)).unwrap();
        }
        let compact_at_4 = rebuild_compact_mmr(&store, 6, 4);

        for i in 4u8..8 {
            store.append(6, 100 + i as u32, hash(i)).unwrap();
        }

        let proof = store.generate_proof(6, 2, 4).unwrap();
        assert!(compact_at_4.verify(&proof, &hash(2)));
    }

    #[test]
    fn proof_ssz_roundtrip_verifies() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        for i in 0u8..5 {
            store.append(9, 200 + i as u32, hash(i)).unwrap();
        }

        let proof = store.generate_proof(9, 3, 5).unwrap();
        let bytes = proof.as_ssz_bytes();
        let decoded = MerkleProofB32::from_ssz_bytes(&bytes).unwrap();

        let compact = rebuild_compact_mmr(&store, 9, 5);
        assert!(compact.verify(&decoded, &hash(3)));
    }
}
