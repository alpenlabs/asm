//! [`ExportEntriesDb`](crate::ExportEntriesDb) implementation backed by sled.
//!
//! Backed by [`strata_merkle_node_store`]: every MMR node is persisted, so a
//! proof is `O(log n)` with no leaf replay. Containers share one node tree,
//! namespaced by `container_id`. Alongside the nodes we keep two small indexes
//! the MMR itself does not carry: the insertion height per leaf, and a reverse
//! `hash → index` map for lookups and append idempotency.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use strata_merkle::{MerkleProofB32, Sha256Hasher};
use strata_merkle_node_store::{LeafPos, MmrNodeStore, NodePos, StoredMmr};

use crate::ExportEntriesDb;

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

/// Sled-backed per-container export-entry store: a namespaced MMR node tree plus
/// a `(container_id, index) → height` map and a reverse
/// `(container_id, hash) → index` map.
#[derive(Debug, Clone)]
pub struct SledExportEntriesDb {
    nodes: sled::Tree,
    heights: sled::Tree,
    index_by_hash: sled::Tree,
}

impl SledExportEntriesDb {
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

    /// Synchronous variant of [`ExportEntriesDb::append_entry`].
    ///
    /// The Moho worker appends entries from its synchronous `ExportEntryStore`
    /// impl while running as an async service, so it calls these sync methods
    /// directly rather than the async trait below.
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

    /// Synchronous variant of [`ExportEntriesDb::put_entries`]. See [`Self::append`].
    ///
    /// Appends `entries` in order, each at `height`, idempotent per entry like
    /// [`Self::append`].
    pub fn put(&self, container_id: u8, height: u32, entries: Vec<[u8; 32]>) -> Result<()> {
        for entry in entries {
            self.append(container_id, height, entry)?;
        }
        Ok(())
    }

    /// Synchronous variant of [`ExportEntriesDb::entry_count`]. See [`Self::append`].
    pub fn num_entries(&self, container_id: u8) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::leaf_count(
            &self.container(container_id),
        )?)
    }

    /// Synchronous variant of [`ExportEntriesDb::prune_entries_from`]. See [`Self::append`].
    ///
    /// Drops every leaf inserted at `height` or above from all containers:
    /// truncates each container's MMR to the leaves below `height` and removes
    /// their height and reverse-index rows. Leaves are appended in ascending
    /// height, so within a container the dropped ones form a contiguous suffix.
    ///
    /// Idempotent and safe to re-run after a crash: the survivor count per
    /// container is derived from the retained `height < target` rows — which
    /// this never deletes — so it is stable across replays. The height rows are
    /// the marker of pending work and are removed last, after the MMR is
    /// truncated and the reverse index cleaned; a prune interrupted before they
    /// are gone leaves the container looking unpruned and re-runs to completion.
    pub fn prune_from(&self, height: u32) -> Result<()> {
        // One pass over the height index: tally the survivors (`height < target`)
        // per container and note which containers carry anything to drop.
        let mut survivors: BTreeMap<u8, u64> = BTreeMap::new();
        let mut to_prune: BTreeSet<u8> = BTreeSet::new();
        for kv in self.heights.iter() {
            let (key, value) = kv?;
            let container_id = key[0];
            let stored = u32::from_be_bytes(value.as_ref().try_into().context("invalid height")?);
            if stored < height {
                *survivors.entry(container_id).or_insert(0) += 1;
            } else {
                to_prune.insert(container_id);
            }
        }

        for container_id in to_prune {
            let keep = survivors.get(&container_id).copied().unwrap_or(0);

            // Truncate the MMR first. Identifying the rows to clean below works
            // off the index trees, not the leaves, so it survives this removing
            // them; doing it first keeps the still-intact height rows as the
            // re-run marker.
            StoredMmr::<Sha256Hasher>::prune_after(
                &self.container(container_id),
                LeafPos::new(keep),
            )?;

            // Clear reverse-index rows pointing past the survivors. Scanning by
            // stored index avoids reading leaf hashes back out of the now
            // truncated MMR.
            let mut stale_hashes = Vec::new();
            for kv in self.index_by_hash.scan_prefix([container_id]) {
                let (key, idx) = kv?;
                if decode_idx(idx.as_ref())? >= keep {
                    stale_hashes.push(key);
                }
            }
            for key in stale_hashes {
                self.index_by_hash.remove(key)?;
            }

            // Clear the height rows last: they mark the prune as pending, so they
            // outlive the MMR truncation and reverse-index cleanup above.
            let mut stale_heights = Vec::new();
            for kv in self.heights.scan_prefix([container_id]) {
                let (key, _) = kv?;
                let idx = u64::from_be_bytes(key[1..].try_into().context("invalid mmr_index")?);
                if idx >= keep {
                    stale_heights.push(key);
                }
            }
            for key in stale_heights {
                self.heights.remove(key)?;
            }
        }
        Ok(())
    }

    /// Synchronous variant of [`ExportEntriesDb::find_entry_index`]. See [`Self::append`].
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

    /// Synchronous variant of [`ExportEntriesDb::get_entry`]. See [`Self::append`].
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

    /// Synchronous variant of [`ExportEntriesDb::generate_entry_proof`]. See [`Self::append`].
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

impl ExportEntriesDb for SledExportEntriesDb {
    type Error = anyhow::Error;

    async fn put_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> Result<()> {
        self.put(container_id, height, entries)
    }

    async fn entry_count(&self, container_id: u8) -> Result<u64> {
        self.num_entries(container_id)
    }

    async fn find_entry_index(
        &self,
        container_id: u8,
        hash: [u8; 32],
    ) -> Result<Option<(u64, u32)>> {
        self.find_index(container_id, &hash)
    }

    async fn get_entry(&self, container_id: u8, mmr_index: u64) -> Result<Option<(u32, [u8; 32])>> {
        self.get(container_id, mmr_index)
    }

    async fn generate_entry_proof(
        &self,
        container_id: u8,
        mmr_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProofB32> {
        self.generate_proof(container_id, mmr_index, at_leaf_count)
    }

    async fn prune_entries_from(&self, height: u32) -> Result<()> {
        self.prune_from(height)
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
    use tokio::runtime::Runtime;

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
        let store = SledExportEntriesDb::open(&db).unwrap();

        assert_eq!(store.append(1, 10, hash(0xa1)).unwrap(), 0);
        assert_eq!(store.append(1, 11, hash(0xa2)).unwrap(), 1);
        assert_eq!(store.append(2, 11, hash(0xb1)).unwrap(), 0);
        assert_eq!(store.append(1, 12, hash(0xa3)).unwrap(), 2);
        assert_eq!(store.append(2, 12, hash(0xb2)).unwrap(), 1);
    }

    #[test]
    fn num_entries_matches_appends() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

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
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 42, hash(0xaa)).unwrap();

        assert!(store.get(1, 1).unwrap().is_none());
        assert!(store.get(2, 0).unwrap().is_none());
    }

    #[test]
    fn get_returns_height_and_hash() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(3, 999, hash(0xcc)).unwrap();

        let (height, got) = store.get(3, 0).unwrap().unwrap();
        assert_eq!(height, 999);
        assert_eq!(got, hash(0xcc));
    }

    #[test]
    fn find_index_returns_match_with_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
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
        let store = SledExportEntriesDb::open(&db).unwrap();

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
    fn rebuild_compact_mmr(store: &SledExportEntriesDb, container_id: u8, size: u64) -> Mmr64B32 {
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
        let store = SledExportEntriesDb::open(&db).unwrap();
        let h = hash(0x01);
        store.append(4, 100, h).unwrap();

        let proof = store.generate_proof(4, 0, 1).unwrap();
        let compact = rebuild_compact_mmr(&store, 4, 1);
        assert!(compact.verify(&proof, &h));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
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
        let store = SledExportEntriesDb::open(&db).unwrap();

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
        let store = SledExportEntriesDb::open(&db).unwrap();
        for i in 0u8..5 {
            store.append(9, 200 + i as u32, hash(i)).unwrap();
        }

        let proof = store.generate_proof(9, 3, 5).unwrap();
        let bytes = proof.as_ssz_bytes();
        let decoded = MerkleProofB32::from_ssz_bytes(&bytes).unwrap();

        let compact = rebuild_compact_mmr(&store, 9, 5);
        assert!(compact.verify(&decoded, &hash(3)));
    }

    #[test]
    fn prune_from_drops_suffix_at_or_above_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        // Container 1: heights 10, 10, 11, 12. Container 2: heights 11, 12.
        store.append(1, 10, hash(0xa0)).unwrap();
        store.append(1, 10, hash(0xa1)).unwrap();
        store.append(1, 11, hash(0xa2)).unwrap();
        store.append(1, 12, hash(0xa3)).unwrap();
        store.append(2, 11, hash(0xb0)).unwrap();
        store.append(2, 12, hash(0xb1)).unwrap();

        store.prune_from(11).unwrap();

        // Only the height-10 leaves of container 1 survive; container 2 is empty.
        assert_eq!(store.num_entries(1).unwrap(), 2);
        assert_eq!(store.num_entries(2).unwrap(), 0);
        assert_eq!(store.get(1, 0).unwrap(), Some((10, hash(0xa0))));
        assert_eq!(store.get(1, 1).unwrap(), Some((10, hash(0xa1))));
        assert!(store.get(1, 2).unwrap().is_none());

        // The reverse index drops the pruned hashes too.
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 10)));
        assert_eq!(store.find_index(1, &hash(0xa2)).unwrap(), None);
        assert_eq!(store.find_index(2, &hash(0xb0)).unwrap(), None);
    }

    #[test]
    fn prune_from_above_tip_is_noop() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, hash(0xa0)).unwrap();
        store.append(1, 11, hash(0xa1)).unwrap();

        store.prune_from(99).unwrap();

        assert_eq!(store.num_entries(1).unwrap(), 2);
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 11)));
    }

    #[test]
    fn prune_from_is_idempotent_and_reappendable() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        for i in 0u8..4 {
            store.append(1, 10 + i as u32, hash(i)).unwrap();
        }

        store.prune_from(11).unwrap();
        // Re-running converges to the same state.
        store.prune_from(11).unwrap();
        assert_eq!(store.num_entries(1).unwrap(), 1);

        // After pruning the MMR is appendable again, assigning the freed indices
        // and producing proofs that verify against a fresh replay.
        assert_eq!(store.append(1, 11, hash(0xc0)).unwrap(), 1);
        assert_eq!(store.append(1, 12, hash(0xc1)).unwrap(), 2);

        let compact = rebuild_compact_mmr(&store, 1, 3);
        let proof = store.generate_proof(1, 2, 3).unwrap();
        assert!(compact.verify(&proof, &hash(0xc1)));
    }

    /// Exercises the async [`ExportEntriesDb`] trait surface, proving the
    /// methods delegate to their synchronous counterparts.
    #[test]
    fn async_trait_delegates_to_sync() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        Runtime::new().unwrap().block_on(async {
            store
                .put_entries(1, 10, vec![hash(0xa1), hash(0xa2)])
                .await
                .unwrap();
            assert_eq!(store.entry_count(1).await.unwrap(), 2);
            assert_eq!(
                store.find_entry_index(1, hash(0xa1)).await.unwrap(),
                Some((0, 10))
            );
            assert_eq!(store.get_entry(1, 0).await.unwrap(), Some((10, hash(0xa1))));

            let proof = store.generate_entry_proof(1, 0, 1).await.unwrap();
            let compact = rebuild_compact_mmr(&store, 1, 1);
            assert!(compact.verify(&proof, &hash(0xa1)));

            store.prune_entries_from(10).await.unwrap();
            assert_eq!(store.entry_count(1).await.unwrap(), 0);
        });
    }
}
