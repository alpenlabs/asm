//! Storage trait for per-container export-entry indexes.
//!
//! [`MohoState`](moho_types::MohoState) keeps only each container's compact MMR
//! (its peaks), so the original 32-byte leaves can't be recovered from it. An
//! export-entries store mirrors those leaves so the RPC can rebuild inclusion
//! proofs on demand. Containers are namespaced by `container_id`; each behaves
//! as an independent MMR over its entry hashes.

use std::fmt::Debug;

use strata_merkle::MerkleProofB32;

/// Persistence interface for the per-container export-entry index.
pub trait ExportEntriesDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Appends an entry for `container_id` and resolves to its `mmr_index`.
    ///
    /// Idempotent: a duplicate `(container_id, entry)` resolves to the original
    /// index unchanged, so block replays after restart are a no-op. Assumes
    /// `(container_id, entry_hash)` is unique within a correct chain.
    fn append_entry(
        &self,
        container_id: u8,
        height: u32,
        entry: [u8; 32],
    ) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Resolves to the number of entries currently stored for `container_id`.
    fn entry_count(
        &self,
        container_id: u8,
    ) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Reverse lookup: resolves to `(mmr_index, insertion_height)` for `hash`
    /// under `container_id`, or `None` if absent.
    fn find_entry_index(
        &self,
        container_id: u8,
        hash: [u8; 32],
    ) -> impl Future<Output = Result<Option<(u64, u32)>, Self::Error>> + Send;

    /// Resolves to `(insertion_height, entry_hash)` at `(container_id, mmr_index)`,
    /// or `None` if absent.
    fn get_entry(
        &self,
        container_id: u8,
        mmr_index: u64,
    ) -> impl Future<Output = Result<Option<(u32, [u8; 32])>, Self::Error>> + Send;

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
}
