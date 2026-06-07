//! Storage trait for the ASM manifest-hash Merkle Mountain Range.
//!
//! The MMR is height-indexed: the manifest hash for the L1 block at height `h`
//! is the leaf at index `h`. It stores manifest *hashes* (not full manifests)
//! and serves `O(log n)` inclusion proofs against the compact-peaks
//! accumulators the rest of the system holds.

use std::fmt::Debug;

use strata_asm_common::AsmManifestHash;
use strata_merkle::MerkleProofB32;

/// Persistence interface for the manifest-hash MMR.
///
/// Async methods with an associated error type.
///
/// Unlike the block-keyed stores this exposes no prune operations: the MMR is a
/// contiguous accumulator anchored at genesis, so leaves cannot be dropped from
/// the bottom without breaking the height-to-index mapping and every proof that
/// walks through them.
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
