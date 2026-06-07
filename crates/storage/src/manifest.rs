//! Storage trait for full ASM manifests.
//!
//! Each entry records the [`AsmManifest`] produced for the L1 block identified
//! by the given [`L1BlockCommitment`]. This is distinct from
//! [`AsmManifestMmrDb`](crate::AsmManifestMmrDb), which stores only manifest
//! *hashes* in a height-indexed MMR for inclusion proofs; this store keeps the
//! full manifest for chaintsn and other consumers.

use std::fmt::Debug;

use strata_asm_common::AsmManifest;
use strata_identifiers::L1BlockCommitment;

/// Persistence interface for full ASM manifest storage.
///
/// Async methods with an associated error type. Unlike the state stores there is
/// no `get_latest`: manifests are only ever looked up for a specific block.
pub trait AsmManifestDb {
    /// The error type returned by database operations.
    type Error: Debug;

    /// Stores the manifest, keyed by its own block commitment (derived from the
    /// manifest's height and block id).
    fn put(&self, manifest: AsmManifest) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves the manifest for the given L1 block commitment, if any.
    fn get(
        &self,
        block: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<AsmManifest>, Self::Error>> + Send;

    /// Prunes all manifests for blocks with height strictly below
    /// `before_height` — routine storage cleanup of old manifests.
    fn prune_before(
        &self,
        before_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Removes all manifests for blocks with height strictly above
    /// `after_height` (which is kept).
    ///
    /// For manual intervention — e.g. rolling storage back to a known-good
    /// height so the worker reprocesses from there.
    fn prune_after(
        &self,
        after_height: u32,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
