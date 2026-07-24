//! Traits for the chain worker to interface with the underlying system.
//!
//! The worker's dependencies split into five concerns, each backed by a
//! distinct subsystem in production:
//!
//! - [`L1DataProvider`] — reads L1 data from the Bitcoin node (blocks, txs, network).
//! - [`AnchorStateStore`] — persists and loads the [`AnchorState`].
//! - [`ManifestMmrStore`] — manifest persistence and the manifest-hash MMR.
//! - [`AuxDataStore`] — per-block [`AuxData`] for prover consumption.
//! - [`SpecActivationStore`] — spec activations discovered from ASM VK upgrade logs.
//!
//! [`WorkerContext`] is the umbrella that combines all five. It has a blanket
//! impl, so an implementor just implements the five concern traits and gets
//! `WorkerContext` for free; consumers that only need one concern can depend on
//! the narrower trait instead of the whole context.

use bitcoin::{Block, Network, block::Header};
use strata_asm_common::{
    AnchorState, AsmManifest, AsmManifestHash, AuxData, MMR_SENTINEL_DUMMY_LEAF,
};
use strata_asm_params::SpecId;
use strata_btc_types::{BitcoinTxid, RawBitcoinTx};
use strata_identifiers::{L1BlockCommitment, L1BlockId, L1Height};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;

use crate::WorkerResult;

/// A discovered spec activation.
///
/// Records that the block at `enacting_height` enacted an ASM VK upgrade
/// whose new artifact implements `version`, activating it from the next block
/// onward and switching the ASM STF predicate to `new_predicate`.
///
/// Worker bookkeeping, not protocol surface: the chain only carries the raw
/// version id in the enacted update's log, and the store persists it that
/// way; this is the act-time form, with the id mapped through [`SpecId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecActivationRecord {
    /// Height of the L1 block whose ASM VK upgrade enactment triggered the
    /// activation.
    pub enacting_height: L1Height,

    /// The activated spec version.
    pub version: SpecId,

    /// The ASM STF predicate the upgrade enacted. Enactment removes the
    /// update from the admin queue and only surfaces it in the emitted log,
    /// so this record is the worker's durable copy of the VK the boundary
    /// switched to.
    pub new_predicate: PredicateKey,
}

impl SpecActivationRecord {
    /// Reassembles a record from its raw stored parts, mapping the raw
    /// version id through [`SpecId`]. Errs with the raw id when this binary
    /// has no variant for it.
    pub fn from_raw(
        enacting_height: L1Height,
        version: u16,
        new_predicate: PredicateKey,
    ) -> Result<Self, u16> {
        Ok(Self {
            enacting_height,
            version: SpecId::try_from(version)?,
            new_predicate,
        })
    }

    /// Height from which the version's rules apply: the block after the
    /// enacting one.
    pub fn activation_height(&self) -> L1Height {
        self.enacting_height.saturating_add(1)
    }
}

/// Reads L1 data from the backing Bitcoin source.
pub trait L1DataProvider {
    /// Fetches a Bitcoin [`Block`] at a given height.
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block>;

    /// Fetches a Bitcoin block [`Header`], without the block's transactions.
    fn get_l1_block_header(&self, blockid: &L1BlockId) -> WorkerResult<Header>;

    /// Fetches the [`Header`] of the active-chain block at a given L1 height.
    ///
    /// Unlike [`get_l1_block_header`](Self::get_l1_block_header), this resolves
    /// by height rather than id. Used at startup to validate the configured
    /// anchor against L1, where the anchor block and its difficulty-epoch start
    /// block are known only by height.
    fn get_l1_block_header_at_height(&self, height: u64) -> WorkerResult<Header>;

    /// Fetches the L1 height of the block with the given id.
    ///
    /// A submitted block carries only its id; the worker resolves it to a
    /// height-tagged [`L1BlockCommitment`] here. Every subsequent height is
    /// derived by the worker itself (the STF chains each block's height from its
    /// parent), so this is the single point where an authoritative height enters.
    fn get_l1_block_height(&self, blockid: &L1BlockId) -> WorkerResult<u64>;

    /// Fetches a raw Bitcoin transaction by txid.
    ///
    /// Returns the raw transaction bytes.
    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx>;

    /// A Bitcoin network identifier.
    fn get_network(&self) -> WorkerResult<Network>;
}

/// Persists and loads the ASM anchor state.
pub trait AnchorStateStore {
    /// Fetches the [`AnchorState`] given the block id.
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AnchorState>;

    /// Fetches the latest [`AnchorState`] — the one at the highest stored block.
    ///
    /// This is a best-effort startup resume hint, *not* a guaranteed canonical
    /// tip. Orphaned states from abandoned reorg branches are never pruned, so
    /// the highest-height entry may belong to a branch that is no longer
    /// canonical (e.g. after a reorg to a shorter chain the orphaned higher
    /// block outranks the canonical tip). Implementations must not assume the
    /// result is on the canonical chain.
    ///
    /// This is safe to use only as the initial anchor seed: every sync re-derives
    /// the base by walking the L1 target's ancestry (see `plan_block_processing`)
    /// and resets the anchor before applying any block, so a stale hint here is
    /// overwritten on the first sync and never drives a transition.
    fn get_latest_anchor_state(&self) -> WorkerResult<Option<AnchorState>>;

    /// Puts the [`AnchorState`] into DB.
    ///
    /// Keyed by the state's own `chain_view.pow_state.last_verified_block`; the
    /// key is derived here rather than passed in, mirroring
    /// [`record_manifest`](ManifestMmrStore::record_manifest), which derives its
    /// height and hash from the manifest.
    fn store_anchor_state(&self, state: &AnchorState) -> WorkerResult<()>;
}

/// Persists L1 manifests and maintains the manifest-hash MMR.
pub trait ManifestMmrStore {
    /// Persists the full [`AsmManifest`] struct.
    ///
    /// Does not touch the MMR — pair with
    /// [`put_manifest_hash`](Self::put_manifest_hash), or call
    /// [`record_manifest`](Self::record_manifest) to do both.
    fn put_manifest(&self, manifest: AsmManifest) -> WorkerResult<()>;

    /// Writes a manifest `hash` to the MMR as the leaf for L1 `height`.
    ///
    /// The MMR is height-indexed (see
    /// [`prefill_manifest_mmr`](Self::prefill_manifest_mmr)): with the genesis
    /// prefill in place, the leaf for `height` lands at index `height`. A
    /// `height` at the current end appends; a `height` below it overwrites the
    /// existing leaf, which is expected during an L1 reorg that replaces the
    /// block at an already-seen height. A `height` past the end is rejected,
    /// since it would leave a gap in the height-to-index mapping.
    ///
    /// The worker only ever calls this in forward order: `sync_to_block`
    /// processes from the base (the most recent ancestor with a stored anchor
    /// state, i.e. the reorg fork point) through the target block, oldest
    /// first, so `height` arrives contiguously and never skips ahead. On a
    /// reorg this overwrites each superseded leaf from the fork point forward
    /// before any later height is written, so a stale leaf never outlives the
    /// chain it belonged to.
    fn put_manifest_hash(&self, height: u64, hash: AsmManifestHash) -> WorkerResult<()>;

    /// Prefills the manifest MMR with sentinel leaves so that real manifests
    /// land at a leaf index equal to their L1 block height.
    ///
    /// The MMR is height-indexed: positions `0..=genesis_height` are filled
    /// with [`MMR_SENTINEL_DUMMY_LEAF`], so the manifest produced for height
    /// `h` appends at leaf index `h`. This mirrors the in-memory (proven) MMR's
    /// genesis prefill.
    ///
    /// Called once at worker startup, before any manifest is appended. The
    /// default appends sentinels from the current leaf count up to and
    /// including `genesis_height`, which makes it idempotent: a no-op once the
    /// MMR already holds `genesis_height + 1` entries, so it is safe to run on
    /// every restart.
    fn prefill_manifest_mmr(&self, genesis_height: u64) -> WorkerResult<()> {
        let sentinel = AsmManifestHash::from(MMR_SENTINEL_DUMMY_LEAF);
        for height in self.manifest_mmr_leaf_count()?..=genesis_height {
            self.put_manifest_hash(height, sentinel)?;
        }
        Ok(())
    }

    /// Persists a manifest in full: the [`AsmManifest`] struct via
    /// [`put_manifest`](Self::put_manifest) and its hash into the
    /// height-indexed MMR via [`put_manifest_hash`](Self::put_manifest_hash).
    ///
    /// Called after each STF execution. Provided as a default that composes the
    /// two primitives, deriving the height and hash from the manifest; backends
    /// implement those primitives, not this.
    fn record_manifest(&self, manifest: AsmManifest) -> WorkerResult<()> {
        let height = u64::from(manifest.height());
        let hash = manifest.compute_hash();
        self.put_manifest(manifest)?;
        self.put_manifest_hash(height, hash)
    }

    /// Returns the number of leaves currently in the MMR — equivalently, the
    /// index at which the next [`put_manifest_hash`](Self::put_manifest_hash)
    /// will append. Used by
    /// [`prefill_manifest_mmr`](Self::prefill_manifest_mmr) to resume
    /// prefilling from the current position.
    fn manifest_mmr_leaf_count(&self) -> WorkerResult<u64>;

    /// Generates an MMR inclusion proof for a leaf at a specific MMR size.
    ///
    /// The `at_leaf_count` parameter specifies the number of leaves that existed
    /// in the MMR when the proof should be constructed. This allows callers to
    /// generate proofs against a historical snapshot of the MMR rather than the
    /// current state.
    ///
    /// Returns a Merkle proof that can be used by a verifier to check the leaf's
    /// inclusion against the corresponding MMR root for that snapshot.
    fn generate_mmr_proof_at(&self, index: u64, at_leaf_count: u64)
    -> WorkerResult<MerkleProofB32>;

    /// Retrieves a manifest hash by its MMR leaf index.
    ///
    /// Reads the hash directly from the MMR structure. Errors with
    /// `ManifestHashNotFound` if no leaf exists at `index`.
    fn get_manifest_hash(&self, index: u64) -> WorkerResult<AsmManifestHash>;
}

/// Persists and loads per-block auxiliary data for the prover.
pub trait AuxDataStore {
    /// Stores [`AuxData`] for a given L1 block.
    ///
    /// This should be called after each STF execution with the auxiliary data
    /// used during the transition, so the prover can use it as input.
    fn store_aux_data(&self, blockid: &L1BlockCommitment, data: &AuxData) -> WorkerResult<()>;

    /// Retrieves [`AuxData`] for a given L1 block. Errors with `MissingAuxData`
    /// if none was stored for `blockid`.
    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> WorkerResult<AuxData>;
}

/// Persists spec activations discovered from ASM VK upgrade logs.
pub trait SpecActivationStore {
    /// Records a discovered spec activation.
    ///
    /// Called *before* the enacting block's anchor state is committed, so an
    /// activation can never lag a committed anchor. Idempotent: crash-replay
    /// of the enacting block rewrites the same record.
    fn record_spec_activation(&self, activation: SpecActivationRecord) -> WorkerResult<()>;

    /// Returns every recorded activation, ascending by enacting height.
    fn list_spec_activations(&self) -> WorkerResult<Vec<SpecActivationRecord>>;

    /// Removes activations whose enacting height is strictly above
    /// `after_height` (which is kept). Called on reorgs so activations enacted
    /// on the abandoned branch are dropped; re-processing the new branch
    /// re-discovers any that survive.
    fn prune_spec_activations_after(&self, after_height: L1Height) -> WorkerResult<()>;
}

/// Context trait for a worker to interact with the database and Bitcoin Client.
///
/// Umbrella over the five concern traits ([`L1DataProvider`],
/// [`AnchorStateStore`], [`ManifestMmrStore`], [`AuxDataStore`],
/// [`SpecActivationStore`]). The blanket impl means any type that implements
/// all five automatically implements `WorkerContext`, so implementors never
/// name it directly.
pub trait WorkerContext:
    L1DataProvider + AnchorStateStore + ManifestMmrStore + AuxDataStore + SpecActivationStore
{
}

impl<T> WorkerContext for T where
    T: L1DataProvider + AnchorStateStore + ManifestMmrStore + AuxDataStore + SpecActivationStore
{
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateTypeId;

    use super::*;

    fn predicate() -> PredicateKey {
        PredicateKey::new(PredicateTypeId::AlwaysAccept, vec![])
    }

    #[test]
    fn activation_is_block_after_enactment() {
        let record = SpecActivationRecord {
            enacting_height: 41,
            version: SpecId::V1,
            new_predicate: predicate(),
        };
        assert_eq!(record.activation_height(), 42);
    }

    /// Raw stored parts round-trip through the typed record; an id this
    /// binary has no variant for surfaces as an error instead of misparsing.
    #[test]
    fn from_raw_maps_known_versions_only() {
        let record = SpecActivationRecord::from_raw(41, SpecId::V1.into(), predicate()).unwrap();
        assert_eq!(record.version, SpecId::V1);
        assert_eq!(
            SpecActivationRecord::from_raw(41, 0xBEEF, predicate()),
            Err(0xBEEF)
        );
    }
}
