//! Storage trait for per-container export-entry indexes.
//!
//! [`MohoState`](moho_types::MohoState) keeps only each container's compact MMR
//! (its peaks), so the original 32-byte leaves can't be recovered from it. An
//! export-entries store mirrors those leaves so the RPC can rebuild inclusion
//! proofs on demand. Containers are namespaced by `container_id`; each behaves
//! as an independent MMR over its entry hashes.

use std::{fmt::Debug, ops::Range};

use strata_merkle::MerkleProofB32;

/// Persistence interface for the per-container export-entry index.
pub trait ExportEntriesDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Appends `entries` for `container_id` in order, each tagged with `height`.
    ///
    /// Mirrors the worker's batched `store_export_entries`: a single block can
    /// contribute several leaves to one container, handed over in one call.
    /// Appends unconditionally and does not deduplicate; a consumer that may
    /// reprocess a block (after a crash or reorg) prunes from the block's height
    /// via [`prune_entries_from`] first, so the leaves it then stores extend a
    /// clean prefix.
    ///
    /// [`prune_entries_from`]: Self::prune_entries_from
    fn append_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Reverse lookup: resolves to the `mmr_index` of `hash` under
    /// `container_id`, or `None` if absent.
    ///
    /// If multiple entries share the same `hash`, only one is returned: the most
    /// recently appended one (the highest `mmr_index`). Consumers for which
    /// duplicate hashes are meaningful must not rely on this and should handle
    /// the ambiguity themselves.
    fn find_entry_index(
        &self,
        container_id: u8,
        hash: [u8; 32],
    ) -> impl Future<Output = Result<Option<u64>, Self::Error>> + Send;

    /// Resolves to the entry hash at `(container_id, mmr_index)`, or `None` if
    /// absent.
    fn get_entry(
        &self,
        container_id: u8,
        mmr_index: u64,
    ) -> impl Future<Output = Result<Option<[u8; 32]>, Self::Error>> + Send;

    /// Resolves to the L1 height at which the leaf at `(container_id, mmr_index)`
    /// was inserted, or `None` if absent.
    fn entry_height(
        &self,
        container_id: u8,
        mmr_index: u64,
    ) -> impl Future<Output = Result<Option<u32>, Self::Error>> + Send;

    /// Generates an inclusion proof for `mmr_index` against the container's MMR
    /// at size `at_leaf_count`.
    fn generate_entry_proof(
        &self,
        container_id: u8,
        mmr_index: u64,
        at_leaf_count: u64,
    ) -> impl Future<Output = Result<MerkleProofB32, Self::Error>> + Send;

    /// Removes every entry inserted at `height` or above, across all containers,
    /// truncating each container's MMR back to the leaves below `height`.
    ///
    /// Used to undo an L1 reorg before the replacement block at `height`
    /// re-appends its own entries. Entries are appended in ascending height, so
    /// those at or above `height` form a contiguous suffix of each container.
    /// Idempotent: pruning an already-pruned range resolves to no change.
    fn prune_entries_from(
        &self,
        height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Resolves to the half-open range of leaf indices `container_id` gained at
    /// `height`, or `None` if no entry was inserted at that height.
    ///
    /// Entries are appended in ascending height, so a height owns a contiguous
    /// run of leaves; the range locates a block's entries within the MMR for,
    /// e.g., rebuilding the proofs it committed to.
    fn entry_range_at_height(
        &self,
        container_id: u8,
        height: u32,
    ) -> impl Future<Output = Result<Option<Range<u64>>, Self::Error>> + Send;
}
