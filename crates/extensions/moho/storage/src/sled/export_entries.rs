//! [`ExportEntriesDb`](crate::ExportEntriesDb) implementation backed by sled.
//!
//! Backed by [`strata_merkle_node_store`]: every MMR node is persisted, so a
//! proof is `O(log n)` with no leaf replay. Containers share one node tree,
//! namespaced by `container_id`. Alongside the nodes we keep two small indexes
//! the MMR itself does not carry: a reverse `hash → index` map for lookups, and
//! a `height → first index` map locating where each block's leaves begin. The
//! latter doubles as the per-leaf height source: runs are contiguous, so the
//! height of any leaf is the height whose run starts at or before its index.
//!
//! Appends are unconditional — the store does not deduplicate. A consumer that
//! might reprocess a block (after a crash or an L1 reorg) prunes from the
//! block's height first, so re-stored leaves always extend a clean prefix.

use std::{collections::BTreeSet, ops::Range};

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

/// One container's view onto the shared trees, with its [`id`](Self::id) the
/// isolation boundary: every key is prefixed with `id`, so each container is an
/// independent MMR with its own height and hash indexes. All per-container reads
/// and writes go through here, and the prefixed keys never escape this type.
/// Implements [`MmrNodeStore`] over the node tree, so the [`StoredMmr`]
/// operations apply directly to `self`.
///
/// Every field below shares the `id`-prefixed key space; the key/value shapes
/// noted on each are the bytes *after* that prefix.
#[derive(Debug)]
struct ContainerView<'a> {
    /// Container this view is scoped to; the prefix on every key.
    id: u8,
    /// MMR nodes, `node_pos → node`. Backs the [`StoredMmr`] that owns leaves,
    /// hashing, and the root.
    nodes: &'a sled::Tree,
    /// Reverse index `entry_hash → mmr_index`, for looking a leaf up by its hash.
    index_by_hash: &'a sled::Tree,
    /// `height → first mmr_index`, the start of the contiguous run of leaves a
    /// height contributed; the run's end is the next populated height (or the
    /// leaf count). Drives [`SledExportEntriesDb::leaf_range_at_height`] and, since
    /// runs are contiguous, the per-leaf height lookup in [`Self::height_at`].
    index_by_height: &'a sled::Tree,
}

impl ContainerView<'_> {
    /// `id || NodePos::to_key()` — key into the MMR node tree.
    fn node_key(&self, pos: NodePos) -> [u8; 10] {
        let mut key = [0u8; 10];
        key[0] = self.id;
        key[1..].copy_from_slice(&pos.to_key());
        key
    }

    /// `id || hash` — key into the reverse `hash → index` map.
    fn hash_key(&self, hash: &[u8; 32]) -> [u8; 33] {
        let mut key = [0u8; 33];
        key[0] = self.id;
        key[1..].copy_from_slice(hash);
        key
    }

    /// `id || height` — key into the `height → first index` map.
    fn height_key(&self, height: u32) -> [u8; 5] {
        let mut key = [0u8; 5];
        key[0] = self.id;
        key[1..].copy_from_slice(&height.to_be_bytes());
        key
    }

    /// See [`SledExportEntriesDb::append`].
    fn append(&self, height: u32, entries: Vec<[u8; 32]>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        // The first leaf of this height lands at the current count; record the
        // run's start. Appends are unconditional — deduplicating reprocessed
        // blocks is the caller's job (it prunes from the block's height first),
        // so the store appends exactly what it is handed.
        self.index_by_height
            .insert(self.height_key(height), &self.num_entries()?.to_be_bytes())?;

        for entry in entries {
            let index = StoredMmr::<Sha256Hasher>::append_leaf(self, entry)?;
            self.index_by_hash
                .insert(self.hash_key(&entry), &index.to_be_bytes())?;
        }
        Ok(())
    }

    /// See [`SledExportEntriesDb::num_entries`].
    fn num_entries(&self) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::leaf_count(self)?)
    }

    /// See [`SledExportEntriesDb::find_index`].
    fn find_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>> {
        let Some(idx_bytes) = self.index_by_hash.get(self.hash_key(hash))? else {
            return Ok(None);
        };
        let mmr_index = decode_idx(idx_bytes.as_ref())?;
        let height = self
            .height_at(mmr_index)?
            .context("secondary index points at missing primary entry")?;
        Ok(Some((mmr_index, height)))
    }

    /// See [`SledExportEntriesDb::get`].
    fn get(&self, mmr_index: u64) -> Result<Option<(u32, [u8; 32])>> {
        let Some(hash) = StoredMmr::<Sha256Hasher>::get_leaf(self, mmr_index)? else {
            return Ok(None);
        };
        let height = self
            .height_at(mmr_index)?
            .context("leaf present but its height is missing")?;
        Ok(Some((height, hash)))
    }

    /// See [`SledExportEntriesDb::leaf_range_at_height`].
    fn leaf_range_at_height(&self, height: u32) -> Result<Option<Range<u64>>> {
        let start_key = self.height_key(height);
        let Some(start_bytes) = self.index_by_height.get(start_key)? else {
            return Ok(None);
        };
        let start = decode_idx(start_bytes.as_ref())?;

        // The end is the start of the next populated height in this container.
        // The next key in the tree could belong to the following container, so
        // bound the scan to this one and fall back to the leaf count.
        let end = match self.index_by_height.get_gt(start_key)? {
            Some((next_key, next_bytes)) if next_key[0] == self.id => {
                decode_idx(next_bytes.as_ref())?
            }
            _ => self.num_entries()?,
        };
        Ok(Some(start..end))
    }

    /// See [`SledExportEntriesDb::generate_proof`].
    fn generate_proof(&self, mmr_index: u64, at_leaf_count: u64) -> Result<MerkleProofB32> {
        let proof =
            StoredMmr::<Sha256Hasher>::generate_proof_at_size(self, mmr_index, at_leaf_count)?;
        Ok(MerkleProofB32::from_generic(&proof))
    }

    /// Drops every leaf this container gained at `from_height` or above,
    /// truncating its MMR back to the leaves below `from_height` and clearing
    /// their reverse-index and height-start rows. A no-op when nothing sits at
    /// or above `from_height`.
    ///
    /// The per-container half of [`SledExportEntriesDb::prune_from`]; its crash
    /// safety is documented there.
    fn prune(&self, from_height: u32) -> Result<()> {
        // keep = the survivor count = the start index of the earliest populated
        // height at or above `from_height`. Leaves are appended in ascending
        // height with monotonic starts, so that start is the boundary between the
        // surviving prefix and the dropped suffix. No populated height reaches
        // `from_height` means nothing to drop.
        let mut keep = None;
        for kv in self.index_by_height.scan_prefix([self.id]) {
            let (key, start_bytes) = kv?;
            let h = u32::from_be_bytes(key[1..].try_into().context("invalid height")?);
            if h >= from_height {
                keep = Some(decode_idx(start_bytes.as_ref())?);
                break;
            }
        }
        let Some(keep) = keep else {
            return Ok(());
        };

        // Truncate the MMR back to the survivors.
        StoredMmr::<Sha256Hasher>::prune_after(self, LeafPos::new(keep))?;

        // Clear reverse-index rows pointing past the survivors. Scanning by
        // stored index avoids reading leaf hashes back out of the now truncated
        // MMR.
        let mut stale_hashes = Vec::new();
        for kv in self.index_by_hash.scan_prefix([self.id]) {
            let (key, idx) = kv?;
            if decode_idx(idx.as_ref())? >= keep {
                stale_hashes.push(key);
            }
        }
        for key in stale_hashes {
            self.index_by_hash.remove(key)?;
        }

        // Clear the height-start rows at or above `from_height` last: they are
        // both the source of `keep` and the marker that this prune is pending, so
        // leaving them until the truncation and reverse-index cleanup are done
        // means a crash mid-prune re-runs the whole operation. Delete them
        // highest-height first so the lowest — the one that yields `keep` —
        // survives longest; a re-run keeps recomputing the same `keep` until that
        // final removal, then sees nothing left at or above `from_height`.
        let mut stale_starts = Vec::new();
        for kv in self.index_by_height.scan_prefix([self.id]) {
            let (key, _) = kv?;
            let h = u32::from_be_bytes(key[1..].try_into().context("invalid height")?);
            if h >= from_height {
                stale_starts.push(key);
            }
        }
        for key in stale_starts.into_iter().rev() {
            self.index_by_height.remove(key)?;
        }
        Ok(())
    }

    /// Resolves the insertion height of the leaf at `mmr_index`.
    ///
    /// The height is derived from [`Self::index_by_height`], which records the
    /// start index of each populated height's run. Runs are appended in ascending
    /// height with monotonically increasing starts, so the run containing
    /// `mmr_index` is the one with the greatest start `<= mmr_index`: scan this
    /// container's height rows in order and keep the last whose start does not
    /// exceed `mmr_index`.
    ///
    /// Returns `None` only when no run starts at or before `mmr_index` — an empty
    /// container — which callers treat as a missing leaf.
    ///
    /// # Performance
    ///
    /// Linear in the number of *populated* heights for this container — one row
    /// each, empty heights have none — rather than a point lookup.
    fn height_at(&self, mmr_index: u64) -> Result<Option<u32>> {
        let mut height = None;
        for kv in self.index_by_height.scan_prefix([self.id]) {
            let (key, start_bytes) = kv?;
            if decode_idx(start_bytes.as_ref())? > mmr_index {
                break;
            }
            height = Some(u32::from_be_bytes(
                key[1..].try_into().context("invalid height bytes")?,
            ));
        }
        Ok(height)
    }
}

impl MmrNodeStore for ContainerView<'_> {
    type Hash = [u8; 32];
    type Error = sled::Error;

    fn get_node(&self, pos: NodePos) -> Result<Option<[u8; 32]>, sled::Error> {
        Ok(self.nodes.get(self.node_key(pos))?.map(decode_node))
    }

    fn put_node(&self, pos: NodePos, value: [u8; 32]) -> Result<(), sled::Error> {
        self.nodes.insert(self.node_key(pos), value.as_slice())?;
        Ok(())
    }

    fn delete_node(&self, pos: NodePos) -> Result<(), sled::Error> {
        self.nodes.remove(self.node_key(pos))?;
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
            batch.remove(self.node_key(*pos).as_slice());
        }
        for (pos, value) in writes {
            let key = self.node_key(*pos);
            batch.insert(key.as_slice(), value.as_slice());
        }
        self.nodes.apply_batch(batch)
    }
}

/// Sled-backed export-entry store: one independent MMR per container, with the
/// indexes needed to look entries up by height or by hash.
///
/// The trees are shared across all containers; every key is namespaced by a
/// leading `container_id` byte (see [`ContainerView`]), so a container behaves as
/// its own isolated MMR.
#[derive(Debug, Clone)]
pub struct SledExportEntriesDb {
    /// The shared trees; per-tree key layouts and semantics are documented on
    /// [`ContainerView`], the per-container view that owns the read/write logic.
    nodes: sled::Tree,
    index_by_hash: sled::Tree,
    index_by_height: sled::Tree,
}

impl SledExportEntriesDb {
    /// Opens or creates the export entries trees in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            nodes: db.open_tree("export_entry_nodes")?,
            index_by_hash: db.open_tree("export_entries_by_hash")?,
            index_by_height: db.open_tree("export_entries_by_height")?,
        })
    }

    /// One container's view onto the shared trees.
    ///
    /// The Moho worker drives these synchronous methods from its
    /// `ExportEntryStore` impl while running as an async service, so it calls
    /// them directly rather than the async [`ExportEntriesDb`] trait below.
    fn container(&self, container_id: u8) -> ContainerView<'_> {
        ContainerView {
            nodes: &self.nodes,
            index_by_hash: &self.index_by_hash,
            index_by_height: &self.index_by_height,
            id: container_id,
        }
    }

    /// Synchronous variant of [`ExportEntriesDb::append_entries`].
    ///
    /// Appends `entries` for `container_id` in MMR order, each at `height`, and
    /// records where the height's run of leaves begins so
    /// [`Self::leaf_range_at_height`] can bracket it. Appends unconditionally:
    /// the caller prunes from a block's height before re-appending, so the store
    /// does not deduplicate.
    pub fn append(&self, container_id: u8, height: u32, entries: Vec<[u8; 32]>) -> Result<()> {
        self.container(container_id).append(height, entries)
    }

    /// The number of entries currently stored for `container_id`.
    pub fn num_entries(&self, container_id: u8) -> Result<u64> {
        self.container(container_id).num_entries()
    }

    /// Synchronous variant of [`ExportEntriesDb::entry_range_at_height`].
    ///
    /// Returns the half-open range of leaf indices `container_id` gained at
    /// `height`, or `None` if no leaf was inserted at that height. Leaves are
    /// appended in ascending height, so a height owns a contiguous run: it
    /// begins at the recorded start index and ends where the next populated
    /// height begins, or at the leaf count if it is the most recent.
    pub fn leaf_range_at_height(
        &self,
        container_id: u8,
        height: u32,
    ) -> Result<Option<Range<u64>>> {
        self.container(container_id).leaf_range_at_height(height)
    }

    /// Synchronous variant of [`ExportEntriesDb::prune_entries_from`].
    ///
    /// Drops every leaf inserted at `height` or above, across all containers,
    /// truncating each container's MMR to the leaves below `height`. Leaves are
    /// appended in ascending height, so the dropped ones form a contiguous
    /// suffix of each container.
    ///
    /// Idempotent and safe to re-run after a crash: each container's height-start
    /// rows at or above `target` are both the source of its truncation point and
    /// the marker that the prune is pending, and are removed last (lowest height
    /// last), so a prune interrupted midway recomputes the same point and re-runs
    /// to completion. See [`ContainerView::prune`].
    pub fn prune_from(&self, height: u32) -> Result<()> {
        // Prune every container that holds leaves; `ContainerView::prune` is a
        // no-op for any whose leaves all sit below `height`.
        let mut containers = BTreeSet::new();
        for kv in self.index_by_height.iter() {
            let (key, _) = kv?;
            containers.insert(key[0]);
        }
        for container_id in containers {
            self.container(container_id).prune(height)?;
        }
        Ok(())
    }

    /// Synchronous variant of [`ExportEntriesDb::find_entry_index`].
    pub fn find_index(&self, container_id: u8, hash: &[u8; 32]) -> Result<Option<(u64, u32)>> {
        self.container(container_id).find_index(hash)
    }

    /// Synchronous variant of [`ExportEntriesDb::get_entry`].
    pub fn get(&self, container_id: u8, mmr_index: u64) -> Result<Option<(u32, [u8; 32])>> {
        self.container(container_id).get(mmr_index)
    }

    /// Synchronous variant of [`ExportEntriesDb::generate_entry_proof`].
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
        self.container(container_id)
            .generate_proof(mmr_index, at_leaf_count)
    }
}

impl ExportEntriesDb for SledExportEntriesDb {
    type Error = anyhow::Error;

    async fn append_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> Result<()> {
        self.append(container_id, height, entries)
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

    async fn entry_range_at_height(
        &self,
        container_id: u8,
        height: u32,
    ) -> Result<Option<Range<u64>>> {
        self.leaf_range_at_height(container_id, height)
    }
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

        store.append(1, 10, vec![hash(0xa1)]).unwrap();
        store.append(1, 11, vec![hash(0xa2)]).unwrap();
        store.append(2, 11, vec![hash(0xb1)]).unwrap();
        store.append(1, 12, vec![hash(0xa3)]).unwrap();
        store.append(2, 12, vec![hash(0xb2)]).unwrap();

        // Indices run from zero per container, in append order.
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((0, 10)));
        assert_eq!(store.find_index(1, &hash(0xa2)).unwrap(), Some((1, 11)));
        assert_eq!(store.find_index(1, &hash(0xa3)).unwrap(), Some((2, 12)));
        assert_eq!(store.find_index(2, &hash(0xb1)).unwrap(), Some((0, 11)));
        assert_eq!(store.find_index(2, &hash(0xb2)).unwrap(), Some((1, 12)));
    }

    #[test]
    fn num_entries_matches_appends() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        assert_eq!(store.num_entries(7).unwrap(), 0);
        store.append(7, 100, (0..5u8).map(hash).collect()).unwrap();
        assert_eq!(store.num_entries(7).unwrap(), 5);
        assert_eq!(store.num_entries(8).unwrap(), 0);
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 42, vec![hash(0xaa)]).unwrap();

        assert!(store.get(1, 1).unwrap().is_none());
        assert!(store.get(2, 0).unwrap().is_none());
    }

    #[test]
    fn get_returns_height_and_hash() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(3, 999, vec![hash(0xcc)]).unwrap();

        let (height, got) = store.get(3, 0).unwrap().unwrap();
        assert_eq!(height, 999);
        assert_eq!(got, hash(0xcc));
    }

    #[test]
    fn find_index_returns_match_with_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 11, vec![hash(0xa1)]).unwrap();
        store.append(1, 12, vec![hash(0xa2)]).unwrap();
        store.append(2, 10, vec![hash(0xa1)]).unwrap(); // same hash, different container

        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 11)));
        assert_eq!(store.find_index(2, &hash(0xa1)).unwrap(), Some((0, 10)));
        assert_eq!(store.find_index(1, &hash(0xff)).unwrap(), None);
        assert_eq!(store.find_index(3, &hash(0xa1)).unwrap(), None);
    }

    #[test]
    fn append_does_not_deduplicate() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        // The store trusts the caller: re-appending the same hash appends it
        // again rather than deduplicating. Reprocessing is the caller's job,
        // handled by pruning first (see `prune_then_reappend_restores_state`).
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        assert_eq!(store.num_entries(1).unwrap(), 2);
    }

    #[test]
    fn prune_then_reappend_restores_state() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 11, vec![hash(0xa1), hash(0xa2)]).unwrap();

        // The consumer's reprocess pattern: prune the block's height, then
        // re-store. The prune — not any store-side dedup — is what makes
        // reprocessing converge to the same state.
        store.prune_from(11).unwrap();
        store.append(1, 11, vec![hash(0xa1), hash(0xa2)]).unwrap();

        assert_eq!(store.num_entries(1).unwrap(), 3);
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 11)));
        assert_eq!(store.find_index(1, &hash(0xa2)).unwrap(), Some((2, 11)));
        assert_eq!(store.leaf_range_at_height(1, 11).unwrap(), Some(1..3));
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
        store.append(4, 100, vec![h]).unwrap();

        let proof = store.generate_proof(4, 0, 1).unwrap();
        let compact = rebuild_compact_mmr(&store, 4, 1);
        assert!(compact.verify(&proof, &h));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        for i in 0u8..8 {
            store.append(5, 1000 + i as u32, vec![hash(i)]).unwrap();
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
            store.append(6, 100 + i as u32, vec![hash(i)]).unwrap();
        }
        let compact_at_4 = rebuild_compact_mmr(&store, 6, 4);

        for i in 4u8..8 {
            store.append(6, 100 + i as u32, vec![hash(i)]).unwrap();
        }

        let proof = store.generate_proof(6, 2, 4).unwrap();
        assert!(compact_at_4.verify(&proof, &hash(2)));
    }

    #[test]
    fn proof_ssz_roundtrip_verifies() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        for i in 0u8..5 {
            store.append(9, 200 + i as u32, vec![hash(i)]).unwrap();
        }

        let proof = store.generate_proof(9, 3, 5).unwrap();
        let bytes = proof.as_ssz_bytes();
        let decoded = MerkleProofB32::from_ssz_bytes(&bytes).unwrap();

        let compact = rebuild_compact_mmr(&store, 9, 5);
        assert!(compact.verify(&decoded, &hash(3)));
    }

    #[test]
    fn leaf_range_at_height_brackets_each_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        // Heights 10 (2 leaves), 12 (1 leaf), 15 (3 leaves); 11, 13, 14 empty.
        store.append(1, 10, vec![hash(0xa0), hash(0xa1)]).unwrap();
        store.append(1, 12, vec![hash(0xa2)]).unwrap();
        store
            .append(1, 15, vec![hash(0xa3), hash(0xa4), hash(0xa5)])
            .unwrap();

        assert_eq!(store.leaf_range_at_height(1, 10).unwrap(), Some(0..2));
        // A populated height ends where the next populated height begins, even
        // across the empty 13/14 gap.
        assert_eq!(store.leaf_range_at_height(1, 12).unwrap(), Some(2..3));
        // The most recent height runs to the leaf count.
        assert_eq!(store.leaf_range_at_height(1, 15).unwrap(), Some(3..6));
        // Heights with no leaves, and an unknown container, resolve to None.
        assert_eq!(store.leaf_range_at_height(1, 11).unwrap(), None);
        assert_eq!(store.leaf_range_at_height(2, 10).unwrap(), None);
    }

    #[test]
    fn leaf_range_at_height_does_not_leak_across_containers() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        // Same height in two containers; the range must stay within container 1
        // and not run into container 2's leaves.
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(2, 11, vec![hash(0xb0), hash(0xb1)]).unwrap();

        assert_eq!(store.leaf_range_at_height(1, 10).unwrap(), Some(0..1));
        assert_eq!(store.leaf_range_at_height(2, 11).unwrap(), Some(0..2));
    }

    #[test]
    fn prune_from_clears_height_starts_and_reappends() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 11, vec![hash(0xa1), hash(0xa2)]).unwrap();

        store.prune_from(11).unwrap();

        // The pruned height's start row is gone; the survivor's stays.
        assert_eq!(store.leaf_range_at_height(1, 11).unwrap(), None);
        assert_eq!(store.leaf_range_at_height(1, 10).unwrap(), Some(0..1));

        // Re-appending at the freed height records a fresh start index.
        store.append(1, 11, vec![hash(0xc0)]).unwrap();
        assert_eq!(store.leaf_range_at_height(1, 11).unwrap(), Some(1..2));
    }

    #[test]
    fn prune_from_drops_suffix_at_or_above_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        // Container 1: heights 10, 10, 11, 12. Container 2: heights 11, 12.
        store.append(1, 10, vec![hash(0xa0), hash(0xa1)]).unwrap();
        store.append(1, 11, vec![hash(0xa2)]).unwrap();
        store.append(1, 12, vec![hash(0xa3)]).unwrap();
        store.append(2, 11, vec![hash(0xb0)]).unwrap();
        store.append(2, 12, vec![hash(0xb1)]).unwrap();

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
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 11, vec![hash(0xa1)]).unwrap();

        store.prune_from(99).unwrap();

        assert_eq!(store.num_entries(1).unwrap(), 2);
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 11)));
    }

    #[test]
    fn prune_from_is_idempotent_and_reappendable() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        for i in 0u8..4 {
            store.append(1, 10 + i as u32, vec![hash(i)]).unwrap();
        }

        store.prune_from(11).unwrap();
        // Re-running converges to the same state.
        store.prune_from(11).unwrap();
        assert_eq!(store.num_entries(1).unwrap(), 1);

        // After pruning the MMR is appendable again, assigning the freed indices
        // and producing proofs that verify against a fresh replay.
        store.append(1, 11, vec![hash(0xc0)]).unwrap();
        store.append(1, 12, vec![hash(0xc1)]).unwrap();
        assert_eq!(store.find_index(1, &hash(0xc0)).unwrap(), Some((1, 11)));
        assert_eq!(store.find_index(1, &hash(0xc1)).unwrap(), Some((2, 12)));

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
                .append_entries(1, 10, vec![hash(0xa1), hash(0xa2)])
                .await
                .unwrap();
            assert_eq!(store.num_entries(1).unwrap(), 2);
            assert_eq!(
                store.find_entry_index(1, hash(0xa1)).await.unwrap(),
                Some((0, 10))
            );
            assert_eq!(store.get_entry(1, 0).await.unwrap(), Some((10, hash(0xa1))));

            let proof = store.generate_entry_proof(1, 0, 1).await.unwrap();
            let compact = rebuild_compact_mmr(&store, 1, 1);
            assert!(compact.verify(&proof, &hash(0xa1)));

            store.prune_entries_from(10).await.unwrap();
            assert_eq!(store.num_entries(1).unwrap(), 0);
        });
    }
}
