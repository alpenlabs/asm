//! History accumulator for ASM.

use strata_asm_manifest_types::{AsmManifest, AsmManifestHash};
use strata_merkle::{MerkleError, Mmr, Mmr64B32, Sha256Hasher};

use crate::{AsmHistoryAccumulatorState, MMR_SENTINEL_DUMMY_LEAF};

/// The hasher used for ASM manifest MMR operations.
///
/// Uses SHA-256 with full 32-byte hash output.
pub type AsmHasher = Sha256Hasher;

pub type AsmMerkleProof = strata_merkle::MerkleProofB32;

impl AsmHistoryAccumulatorState {
    /// Creates a new height-indexed manifest MMR for the given genesis height.
    ///
    /// The MMR is prefilled with [`MMR_SENTINEL_DUMMY_LEAF`] for every L1 block
    /// height up to and including `genesis_height`, so that the first appended
    /// real manifest (for height `genesis_height + 1`) lands at MMR leaf index
    /// `genesis_height + 1` — i.e. MMR leaf indices equal L1 block heights.
    pub fn new(genesis_height: u64) -> Self {
        let prefill_count = genesis_height + 1;
        let manifest_mmr =
            <Mmr64B32 as Mmr<AsmHasher>>::new_repeated(MMR_SENTINEL_DUMMY_LEAF, prefill_count);
        Self { manifest_mmr }
    }

    /// Returns the current number of leaves in the manifest MMR.
    pub fn num_entries(&self) -> u64 {
        self.manifest_mmr.num_entries()
    }

    /// Returns the L1 block height of the last manifest inserted into the MMR.
    ///
    /// Because the MMR is height-indexed via sentinel prefill, this is simply
    /// `num_entries() - 1`. Returns `genesis_height` if no real manifests have
    /// been appended yet (in that case all entries are prefill sentinels).
    pub fn last_inserted_height(&self) -> u64 {
        self.manifest_mmr.num_entries() - 1
    }

    /// Verifies a Merkle proof for a leaf in the MMR.
    pub fn verify_manifest_leaf(&self, proof: &AsmMerkleProof, leaf: &AsmManifestHash) -> bool {
        self.manifest_mmr.verify(proof, leaf.as_ref())
    }

    /// Adds a new leaf to the MMR.
    pub fn add_manifest_leaf(&mut self, leaf: AsmManifestHash) -> Result<(), MerkleError> {
        Mmr::<AsmHasher>::add_leaf(&mut self.manifest_mmr, *leaf.as_ref())
    }

    pub fn verify_manifest(&mut self, proof: &AsmMerkleProof, manifest: AsmManifest) -> bool {
        let leaf_hash = manifest.compute_hash();
        self.verify_manifest_leaf(proof, &leaf_hash)
    }

    pub fn add_manifest(&mut self, manifest: &AsmManifest) -> Result<(), MerkleError> {
        let leaf_hash = manifest.compute_hash();
        self.add_manifest_leaf(leaf_hash)
    }
}
