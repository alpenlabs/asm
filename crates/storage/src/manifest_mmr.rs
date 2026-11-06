//! Storage trait for the ASM manifest-hash Merkle Mountain Range.
//!
//! The MMR is height-indexed: the manifest hash for the L1 block at height `h`
//! is the leaf at index `h`. It stores manifest *hashes* (not full manifests)
//! and serves `O(log n)` inclusion proofs against the compact-peaks
//! accumulators the rest of the system holds.

use std::fmt::Debug;

use strata_asm_common::AsmManifestHash;
use strata_merkle::{MerkleProofB32, Mmr64B32};

/// Persistence interface for the manifest-hash MMR.
///
/// Async methods with an associated error type.
///
/// Unlike the block-keyed stores this exposes no prune operations: aux
/// resolution must be able to prove any leaf above genesis. The only leaves
/// never stored are the ones at and below genesis, which
/// [`seed`](Self::seed) replaces with their peaks.
pub trait AsmManifestMmrDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Returns the current leaf count.
    fn leaf_count(&self) -> impl Future<Output = Result<u64, Self::Error>> + Send;

    /// Writes a manifest `hash` as the leaf at `height`.
    ///
    /// `height` must be the current end (an append) or an existing index (an
    /// overwrite); a gap past the end is rejected.
    fn put_leaf(
        &self,
        height: u64,
        hash: AsmManifestHash,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Seeds an empty MMR with the peaks of `prefix` and none of its leaves.
    ///
    /// Afterwards the leaf count is `prefix.num_entries()`. Later leaves append
    /// and prove as if the prefix leaves were stored. The prefix leaves cannot
    /// be proven or overwritten, and read as absent unless a leaf is itself a
    /// peak. Errors if the MMR already holds leaves.
    fn seed(&self, prefix: &Mmr64B32) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves a manifest hash by its leaf index.
    fn get_leaf(
        &self,
        index: u64,
    ) -> impl Future<Output = Result<Option<AsmManifestHash>, Self::Error>> + Send;

    /// Generates an inclusion proof for the leaf at `index` against an MMR of
    /// exactly `at_leaf_count` leaves.
    fn generate_proof(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> impl Future<Output = Result<MerkleProofB32, Self::Error>> + Send;
}
