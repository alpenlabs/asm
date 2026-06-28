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

use std::ops::Range;

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

/// Encodes an mmr index as its 8-byte big-endian stored form.
fn encode_idx(idx: u64) -> [u8; 8] {
    idx.to_be_bytes()
}

/// Decodes a stored 8-byte big-endian value into an mmr index.
///
/// Like [`decode_node`], the store only ever writes 8-byte indices, so a wrong
/// length is disk corruption rather than a recoverable condition.
fn decode_idx(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("mmr index value must be 8 bytes"))
}

/// Encodes a block height as its 4-byte big-endian stored form, the suffix of
/// every height-indexed key.
fn encode_height(height: u32) -> [u8; 4] {
    height.to_be_bytes()
}

/// Decodes the 4-byte big-endian height suffix of a height-index key.
///
/// Like [`decode_idx`], the store only ever writes 4-byte heights, so a wrong
/// length is disk corruption rather than a recoverable condition.
fn decode_height(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("mmr height key must be 4 bytes"))
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
    /// runs are contiguous, the per-leaf height lookup in [`Self::entry_height`].
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
        key[1..].copy_from_slice(&encode_height(height));
        key
    }
}

impl ContainerView<'_> {
    /// See [`SledExportEntriesDb::append`].
    fn append(&self, height: u32, entries: Vec<[u8; 32]>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        // The first leaf of this height lands at the current count; record the
        // run's start so `leaf_range_at_height` can bracket it.
        self.index_by_height
            .insert(self.height_key(height), &encode_idx(self.num_entries()?))?;

        for entry in entries {
            let index = StoredMmr::<Sha256Hasher>::append_leaf(self, entry)?;
            self.index_by_hash
                .insert(self.hash_key(&entry), &encode_idx(index))?;
        }
        Ok(())
    }

    /// See [`SledExportEntriesDb::get`].
    fn get(&self, mmr_index: u64) -> Result<Option<[u8; 32]>> {
        Ok(StoredMmr::<Sha256Hasher>::get_leaf(self, mmr_index)?)
    }

    /// See [`SledExportEntriesDb::num_entries`].
    fn num_entries(&self) -> Result<u64> {
        Ok(StoredMmr::<Sha256Hasher>::leaf_count(self)?)
    }

    /// See [`SledExportEntriesDb::generate_proof`].
    fn generate_proof(&self, mmr_index: u64, at_leaf_count: u64) -> Result<MerkleProofB32> {
        let proof =
            StoredMmr::<Sha256Hasher>::generate_proof_at_size(self, mmr_index, at_leaf_count)?;
        Ok(MerkleProofB32::from_generic(&proof))
    }

    /// See [`SledExportEntriesDb::find_index`].
    fn find_index(&self, hash: &[u8; 32]) -> Result<Option<u64>> {
        let Some(idx_bytes) = self.index_by_hash.get(self.hash_key(hash))? else {
            return Ok(None);
        };
        Ok(Some(decode_idx(idx_bytes.as_ref())))
    }

    /// See [`SledExportEntriesDb::entry_height`].
    ///
    /// The height is derived from [`Self::index_by_height`], which records the
    /// start index of each populated height's run. Runs are appended in ascending
    /// height with monotonically increasing starts, so the run containing
    /// `mmr_index` is the one with the greatest start `<= mmr_index`: scan this
    /// container's height rows in order and keep the last whose start does not
    /// exceed `mmr_index`.
    ///
    /// # Performance
    ///
    /// Linear in the number of *populated* heights for this container — one row
    /// each, empty heights have none — rather than a point lookup.
    fn entry_height(&self, mmr_index: u64) -> Result<Option<u32>> {
        // Guard on leaf presence so an out-of-range index resolves to `None`
        // rather than the height of the last run the scan below would settle on.
        if StoredMmr::<Sha256Hasher>::get_leaf(self, mmr_index)?.is_none() {
            return Ok(None);
        }

        let mut height = None;
        for kv in self.index_by_height.scan_prefix([self.id]) {
            let (key, start_bytes) = kv?;
            if decode_idx(start_bytes.as_ref()) > mmr_index {
                break;
            }
            height = Some(decode_height(&key[1..]));
        }
        // The leaf is present (guarded above), so its run must exist.
        height
            .context("leaf present but its height is missing")
            .map(Some)
    }

    /// Drops every leaf this container gained at `from_height` or above,
    /// truncating its MMR back to the leaves below `from_height` and clearing
    /// their reverse-index and height-start rows. A no-op when nothing sits at
    /// or above `from_height`.
    ///
    /// The per-container half of [`SledExportEntriesDb::prune_from`]. The three
    /// mutating steps run in a crash-safe order: drop the leaves, then the
    /// reverse-index rows, and only then the height-start rows. Those rows are
    /// both the source of the cutoff and the marker that a prune is pending, so
    /// removing them last means a crash mid-prune recomputes the same cutoff and
    /// re-runs to completion. See each step for its own invariants.
    fn prune(&self, from_height: u32) -> Result<()> {
        let Some(first_dropped) = self.first_dropped_index(from_height)? else {
            return Ok(());
        };
        self.drop_leaves_from(first_dropped)?;
        self.drop_hash_rows_from(first_dropped)?;
        self.drop_height_rows_from(from_height)?;
        Ok(())
    }

    /// The index of the first leaf to drop: the start of the earliest populated
    /// height at or above `from_height`. Leaves below it survive; it and every
    /// leaf after it are dropped. `None` when no populated height reaches
    /// `from_height`, meaning there is nothing to drop.
    ///
    /// Leaves are appended in ascending height with monotonic start indices, so
    /// the first height at or above `from_height` owns the lowest dropped index.
    /// Two `O(log n)` seeks find it: the cutoff itself if that height is
    /// populated, else the next populated height above it. On forward progress —
    /// the common per-block prune, where nothing sits at or above `from_height` —
    /// both miss within this container without scanning its height rows.
    fn first_dropped_index(&self, from_height: u32) -> Result<Option<u64>> {
        let cutoff = self.height_key(from_height);

        // The cutoff height is itself populated: its run is the first dropped.
        if let Some(start_bytes) = self.index_by_height.get(cutoff)? {
            return Ok(Some(decode_idx(start_bytes.as_ref())));
        }

        // Otherwise the first populated height above it. The next key could
        // belong to the following container, so bound the seek to this one.
        match self.index_by_height.get_gt(cutoff)? {
            Some((next_key, start_bytes)) if next_key[0] == self.id => {
                Ok(Some(decode_idx(start_bytes.as_ref())))
            }
            _ => Ok(None),
        }
    }

    /// Truncates the MMR to the leaves below `first_dropped`, discarding that
    /// leaf and every one after it.
    fn drop_leaves_from(&self, first_dropped: u64) -> Result<()> {
        StoredMmr::<Sha256Hasher>::prune_after(self, LeafPos::new(first_dropped))?;
        Ok(())
    }

    /// Removes the reverse-index rows whose stored index is at or past
    /// `first_dropped`, i.e. the entries [`Self::drop_leaves_from`] discarded.
    ///
    /// Scans by stored index rather than reading leaf hashes back out of the now
    /// truncated MMR.
    fn drop_hash_rows_from(&self, first_dropped: u64) -> Result<()> {
        let mut stale = Vec::new();
        for kv in self.index_by_hash.scan_prefix([self.id]) {
            let (key, idx) = kv?;
            if decode_idx(idx.as_ref()) >= first_dropped {
                stale.push(key);
            }
        }
        for key in stale {
            self.index_by_hash.remove(key)?;
        }
        Ok(())
    }

    /// Removes the height-start rows at or above `from_height`, highest height
    /// first.
    ///
    /// These rows are the prune's pending-marker, so they must be cleared last
    /// (after the leaves and reverse-index rows) and highest-first: the lowest —
    /// the one [`Self::first_dropped_index`] derives the cutoff from — survives
    /// longest, so a re-run after a crash keeps recomputing the same cutoff until
    /// that final removal, then sees nothing left at or above `from_height`.
    fn drop_height_rows_from(&self, from_height: u32) -> Result<()> {
        let mut stale = Vec::new();
        for kv in self.index_by_height.scan_prefix([self.id]) {
            let (key, _) = kv?;
            let h = decode_height(&key[1..]);
            if h >= from_height {
                stale.push(key);
            }
        }
        for key in stale.into_iter().rev() {
            self.index_by_height.remove(key)?;
        }
        Ok(())
    }

    /// See [`SledExportEntriesDb::leaf_range_at_height`].
    fn leaf_range_at_height(&self, height: u32) -> Result<Option<Range<u64>>> {
        let start_key = self.height_key(height);
        let Some(start_bytes) = self.index_by_height.get(start_key)? else {
            return Ok(None);
        };
        let start = decode_idx(start_bytes.as_ref());

        // The end is the start of the next populated height in this container.
        // The next key in the tree could belong to the following container, so
        // bound the scan to this one and fall back to the leaf count.
        let end = match self.index_by_height.get_gt(start_key)? {
            Some((next_key, next_bytes)) if next_key[0] == self.id => {
                decode_idx(next_bytes.as_ref())
            }
            _ => self.num_entries()?,
        };
        Ok(Some(start..end))
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
/// leading `container_id` byte, so a container behaves as
/// its own isolated MMR.
///
/// The synchronous methods below are the primary surface: the Moho worker drives
/// them from its `ExportEntryStore` impl while running as an async service, so it
/// calls them directly rather than the async [`ExportEntriesDb`] trait at the
/// bottom of this file.
#[derive(Debug, Clone)]
pub struct SledExportEntriesDb {
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
    /// to completion. See `ContainerView::prune`.
    pub fn prune_from(&self, height: u32) -> Result<()> {
        // Container ids span the whole `u8` domain, so prune every possible one
        // rather than first scanning the height index to discover which exist.
        // `ContainerView::prune` is a cheap no-op for a container with no leaves
        // at or above `height` (including one that holds none at all).
        for container_id in 0..=u8::MAX {
            self.container(container_id).prune(height)?;
        }
        Ok(())
    }

    /// Synchronous variant of [`ExportEntriesDb::find_entry_index`].
    pub fn find_index(&self, container_id: u8, hash: &[u8; 32]) -> Result<Option<u64>> {
        self.container(container_id).find_index(hash)
    }

    /// Synchronous variant of [`ExportEntriesDb::get_entry`].
    pub fn get(&self, container_id: u8, mmr_index: u64) -> Result<Option<[u8; 32]>> {
        self.container(container_id).get(mmr_index)
    }

    /// Synchronous variant of [`ExportEntriesDb::entry_height`].
    pub fn entry_height(&self, container_id: u8, mmr_index: u64) -> Result<Option<u32>> {
        self.container(container_id).entry_height(mmr_index)
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

    async fn find_entry_index(&self, container_id: u8, hash: [u8; 32]) -> Result<Option<u64>> {
        self.find_index(container_id, &hash)
    }

    async fn get_entry(&self, container_id: u8, mmr_index: u64) -> Result<Option<[u8; 32]>> {
        self.get(container_id, mmr_index)
    }

    async fn entry_height(&self, container_id: u8, mmr_index: u64) -> Result<Option<u32>> {
        SledExportEntriesDb::entry_height(self, container_id, mmr_index)
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
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some(0));
        assert_eq!(store.find_index(1, &hash(0xa2)).unwrap(), Some(1));
        assert_eq!(store.find_index(1, &hash(0xa3)).unwrap(), Some(2));
        assert_eq!(store.find_index(2, &hash(0xb1)).unwrap(), Some(0));
        assert_eq!(store.find_index(2, &hash(0xb2)).unwrap(), Some(1));
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
    fn get_returns_hash() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(3, 999, vec![hash(0xcc)]).unwrap();

        assert_eq!(store.get(3, 0).unwrap(), Some(hash(0xcc)));
    }

    #[test]
    fn entry_height_resolves_insertion_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(3, 100, vec![hash(0xc0)]).unwrap();
        store.append(3, 105, vec![hash(0xc1), hash(0xc2)]).unwrap();

        assert_eq!(store.entry_height(3, 0).unwrap(), Some(100));
        assert_eq!(store.entry_height(3, 1).unwrap(), Some(105));
        assert_eq!(store.entry_height(3, 2).unwrap(), Some(105));
        // Out-of-range indices and unknown containers resolve to None rather than
        // the most recent run's height.
        assert_eq!(store.entry_height(3, 3).unwrap(), None);
        assert_eq!(store.entry_height(4, 0).unwrap(), None);
    }

    #[test]
    fn find_index_returns_match() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 11, vec![hash(0xa1)]).unwrap();
        store.append(1, 12, vec![hash(0xa2)]).unwrap();
        store.append(2, 10, vec![hash(0xa1)]).unwrap(); // same hash, different container

        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some(1));
        assert_eq!(store.find_index(2, &hash(0xa1)).unwrap(), Some(0));
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
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some(1));
        assert_eq!(store.find_index(1, &hash(0xa2)).unwrap(), Some(2));
        assert_eq!(store.leaf_range_at_height(1, 11).unwrap(), Some(1..3));
    }

    /// Reference compact-peaks MMR built by replaying the first `size` leaves
    /// of `container_id`, matching the accumulators that proofs verify against.
    fn rebuild_compact_mmr(store: &SledExportEntriesDb, container_id: u8, size: u64) -> Mmr64B32 {
        let mut compact = Mmr64B32::new_empty();
        for i in 0..size {
            let hash = store.get(container_id, i).unwrap().unwrap();
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
    fn leaf_range_at_height_ends_at_own_next_height_despite_interleaved_heights() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();

        // Container 2's height (15) is numerically between container 1's heights
        // (10 and 20), but the `id` key prefix keeps each container contiguous in
        // the tree, ordered as 1||10, 1||20, 2||15. So a height's run ends at its
        // own container's next height — `get_gt` never steps across the boundary
        // and back.
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 20, vec![hash(0xa1)]).unwrap();
        store.append(2, 15, vec![hash(0xb0)]).unwrap();

        // Height 10 ends at height 20's start (index 1), not at container 2's leaf.
        assert_eq!(store.leaf_range_at_height(1, 10).unwrap(), Some(0..1));
        // Height 20 is the last in container 1, so it runs to that container's
        // leaf count.
        assert_eq!(store.leaf_range_at_height(1, 20).unwrap(), Some(1..2));
        assert_eq!(store.leaf_range_at_height(2, 15).unwrap(), Some(0..1));
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
        assert_eq!(store.get(1, 0).unwrap(), Some(hash(0xa0)));
        assert_eq!(store.get(1, 1).unwrap(), Some(hash(0xa1)));
        assert!(store.get(1, 2).unwrap().is_none());
        assert_eq!(store.entry_height(1, 1).unwrap(), Some(10));

        // The reverse index drops the pruned hashes too.
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some(1));
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
        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some(1));
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
        assert_eq!(store.find_index(1, &hash(0xc0)).unwrap(), Some(1));
        assert_eq!(store.find_index(1, &hash(0xc1)).unwrap(), Some(2));

        let compact = rebuild_compact_mmr(&store, 1, 3);
        let proof = store.generate_proof(1, 2, 3).unwrap();
        assert!(compact.verify(&proof, &hash(0xc1)));
    }

    // The remaining tests exercise the individual steps `ContainerView::prune`
    // composes, in isolation, so a regression in one is attributable on its own.
    // Driving a single step leaves the container's other indexes intentionally
    // out of sync with the MMR — that is the point of the isolation.

    #[test]
    fn first_dropped_index_finds_first_run_at_or_above_height() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        // Heights 10 (2 leaves, start 0), 12 (1 leaf, start 2), 15 (3 leaves,
        // start 3); 11, 13, 14 empty.
        store.append(1, 10, vec![hash(0xa0), hash(0xa1)]).unwrap();
        store.append(1, 12, vec![hash(0xa2)]).unwrap();
        store
            .append(1, 15, vec![hash(0xa3), hash(0xa4), hash(0xa5)])
            .unwrap();

        let c = store.container(1);
        // A height that is itself populated resolves to its own start.
        assert_eq!(c.first_dropped_index(10).unwrap(), Some(0));
        assert_eq!(c.first_dropped_index(12).unwrap(), Some(2));
        assert_eq!(c.first_dropped_index(15).unwrap(), Some(3));
        // An empty height resolves to the next populated run's start.
        assert_eq!(c.first_dropped_index(11).unwrap(), Some(2));
        assert_eq!(c.first_dropped_index(13).unwrap(), Some(3));
        // Below every run: the whole container is dropped.
        assert_eq!(c.first_dropped_index(0).unwrap(), Some(0));
        // Above the tip, and an empty container: nothing to drop.
        assert_eq!(c.first_dropped_index(16).unwrap(), None);
        assert_eq!(store.container(2).first_dropped_index(0).unwrap(), None);
    }

    #[test]
    fn drop_leaves_from_drops_the_leaf_suffix() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, (0..5u8).map(hash).collect()).unwrap();

        store.container(1).drop_leaves_from(2).unwrap();

        assert_eq!(store.num_entries(1).unwrap(), 2);
        assert_eq!(store.get(1, 1).unwrap(), Some(hash(1)));
        assert!(store.get(1, 2).unwrap().is_none());
    }

    #[test]
    fn drop_hash_rows_from_removes_rows_at_or_past_cutoff() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, (0..4u8).map(hash).collect()).unwrap();
        store.append(2, 10, vec![hash(0xb0)]).unwrap();

        store.container(1).drop_hash_rows_from(2).unwrap();

        // Rows below the cutoff survive; those at or past it are gone.
        assert_eq!(store.find_index(1, &hash(0)).unwrap(), Some(0));
        assert_eq!(store.find_index(1, &hash(1)).unwrap(), Some(1));
        assert_eq!(store.find_index(1, &hash(2)).unwrap(), None);
        assert_eq!(store.find_index(1, &hash(3)).unwrap(), None);
        // Another container's reverse index is untouched.
        assert_eq!(store.find_index(2, &hash(0xb0)).unwrap(), Some(0));
    }

    #[test]
    fn drop_height_rows_from_removes_rows_at_or_above() {
        let db = test_db();
        let store = SledExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, vec![hash(0xa0)]).unwrap();
        store.append(1, 12, vec![hash(0xa1)]).unwrap();
        store.append(1, 15, vec![hash(0xa2)]).unwrap();
        store.append(2, 12, vec![hash(0xb0)]).unwrap();

        let c = store.container(1);
        c.drop_height_rows_from(12).unwrap();

        // The height-10 start row survives; the rows at or above 12 are gone, so
        // `first_dropped_index` can no longer reach them.
        assert_eq!(c.first_dropped_index(10).unwrap(), Some(0));
        assert_eq!(c.first_dropped_index(12).unwrap(), None);
        // Another container's height index is untouched.
        assert_eq!(store.container(2).first_dropped_index(12).unwrap(), Some(0));
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
                Some(0)
            );
            assert_eq!(store.get_entry(1, 0).await.unwrap(), Some(hash(0xa1)));
            assert_eq!(
                ExportEntriesDb::entry_height(&store, 1, 0).await.unwrap(),
                Some(10)
            );

            let proof = store.generate_entry_proof(1, 0, 1).await.unwrap();
            let compact = rebuild_compact_mmr(&store, 1, 1);
            assert!(compact.verify(&proof, &hash(0xa1)));

            store.prune_entries_from(10).await.unwrap();
            assert_eq!(store.num_entries(1).unwrap(), 0);
        });
    }
}
