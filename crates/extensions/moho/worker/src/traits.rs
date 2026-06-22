//! Storage traits the Moho worker interfaces through.
//!
//! The worker derives each [`MohoState`] from the ASM anchor state the ASM
//! worker already committed, chaining it onto the Moho state of the block's
//! parent, then persists it. Those concerns are split into separate traits so
//! an implementor can back them with whatever subsystem it likes:
//!
//! - [`AsmStateProvider`] — reads the [`AnchorState`] and [`AsmLogEntry`]s the Moho state is
//!   computed from.
//! - [`L1ProviderContext`] — resolves the parent of an L1 block commitment, so the fold can chain
//!   onto the parent's Moho state across reorgs.
//! - [`MohoStateStore`] — persists and loads the derived [`MohoState`].
//! - [`ExportEntryStore`] — persists the per-container export-entry leaves the state's
//!   `ExportState` MMR commits to, so inclusion proofs can be rebuilt later.
//!
//! [`MohoWorkerContext`] is the umbrella with a blanket impl, mirroring
//! `strata-asm-worker`'s [`WorkerContext`](strata_asm_worker::WorkerContext):
//! implement the concern traits and get the context for free.

use moho_types::MohoState;
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_identifiers::L1BlockCommitment;

use crate::MohoWorkerResult;

/// Reads the ASM anchor states and logs the Moho worker derives from.
pub trait AsmStateProvider {
    /// Fetches the [`AnchorState`] committed by the ASM worker for `blockid`.
    ///
    /// Errors with [`MissingAsmState`](crate::MohoWorkerError::MissingAsmState)
    /// when no anchor state exists for the block.
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<AnchorState>;

    /// Fetches the [`AsmLogEntry`]s the ASM worker emitted for `blockid`.
    ///
    /// Committed alongside the anchor state, so this errors with
    /// [`MissingAsmState`](crate::MohoWorkerError::MissingAsmState) when the
    /// block's ASM commit is absent. An empty vec means the block had no logs.
    fn get_anchor_logs(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<Vec<AsmLogEntry>>;

    /// Fetches the latest L1 block the ASM worker has committed an anchor state
    /// for, or `None` when the ASM store is empty.
    ///
    /// This is the tip the worker's startup sync catches up to: the ASM
    /// worker commits a block's anchor state before the Moho worker folds it, so
    /// on restart the Moho store can trail this tip. See
    /// [`sync_to_tip`](crate::sync_to_tip).
    fn get_latest_asm_block(&self) -> MohoWorkerResult<Option<L1BlockCommitment>>;
}

/// Resolves L1 block ancestry so the fold can chain onto the parent's state.
pub trait L1ProviderContext {
    /// Fetches the parent of `block` — the commitment whose Moho state the fold
    /// for `block` chains forward from.
    ///
    /// Resolving the real parent (rather than assuming the commit is the
    /// height-successor of the last one processed) is what lets the worker
    /// follow L1 reorgs. Errors with
    /// [`MissingParentBlock`](crate::MohoWorkerError::MissingParentBlock) when
    /// the parent cannot be resolved.
    fn get_parent_block(&self, block: &L1BlockCommitment) -> MohoWorkerResult<L1BlockCommitment>;
}

/// Persists and loads the derived per-block [`MohoState`].
pub trait MohoStateStore {
    /// Fetches the most recently committed [`MohoState`] and the block it is
    /// anchored to, or `None` if the store is empty. Used to resume across
    /// restarts.
    fn get_latest_moho_state(&self) -> MohoWorkerResult<Option<(L1BlockCommitment, MohoState)>>;

    /// Fetches the [`MohoState`] committed for `blockid`.
    ///
    /// Errors with [`MissingMohoState`](crate::MohoWorkerError::MissingMohoState)
    /// when no Moho state exists for the block.
    fn get_moho_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<MohoState>;

    /// Persists the [`MohoState`] derived for `blockid`.
    fn store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &MohoState,
    ) -> MohoWorkerResult<()>;
}

/// Persists the per-container export-entry leaves the derived state commits to.
///
/// [`MohoState`] keeps only each container's compact `ExportState` MMR (its
/// peaks), so the original leaves cannot be recovered from it. The worker
/// mirrors them here as it folds each block — from the same `NewExportEntry`
/// logs that advance the MMR — so the RPC can rebuild inclusion proofs.
pub trait ExportEntryStore {
    /// Stores the export-entry leaves for `container_id` inserted at `height`,
    /// in MMR-append order.
    ///
    /// A single block can append several leaves to one container's MMR, so the
    /// worker hands them over per container in one call rather than one leaf at
    /// a time.
    ///
    /// Appends unconditionally — the store does not deduplicate. Before
    /// reprocessing a block (after a crash or an L1 reorg) the worker first
    /// prunes its height via [`Self::prune_export_entries_from`], so the leaves it
    /// then stores always extend a clean prefix.
    fn store_export_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> MohoWorkerResult<()>;

    /// Drops every export-entry leaf inserted at `height` or above, across all
    /// containers, rolling each container's MMR back to the leaves contributed
    /// by blocks below `height`.
    ///
    /// Called when an L1 reorg replaces the block at `height`: the replacement
    /// can append a different set of leaves than the block it evicts, so the
    /// stale leaves — and everything appended after them — must be cleared
    /// before the new block is folded and re-appends its own. The worker folds
    /// blocks in ascending height, so the leaves at or above `height` are always
    /// a contiguous suffix of each container's MMR.
    ///
    /// Must be idempotent in `height`: like [`Self::store_export_entries`], this runs
    /// before the block's commit point, so a crash mid-reorg has the worker
    /// reprocess the block and prune again. Pruning an already-pruned range must
    /// be a no-op.
    fn prune_export_entries_from(&self, height: u32) -> MohoWorkerResult<()>;
}

/// Context the Moho worker interacts with the outside world through.
///
/// Umbrella over [`AsmStateProvider`], [`L1ProviderContext`], [`MohoStateStore`]
/// and [`ExportEntryStore`]. The blanket impl means any type implementing all
/// four automatically implements `MohoWorkerContext`, so implementors never name
/// it directly.
pub trait MohoWorkerContext:
    AsmStateProvider + L1ProviderContext + MohoStateStore + ExportEntryStore
{
}

impl<T> MohoWorkerContext for T where
    T: AsmStateProvider + L1ProviderContext + MohoStateStore + ExportEntryStore
{
}
