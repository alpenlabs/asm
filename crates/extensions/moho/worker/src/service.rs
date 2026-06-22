//! Service-framework integration for the Moho worker.
//!
//! The worker is an [`AsyncService`] driven by the ASM worker's per-block
//! subscription (a [`Subscription<L1BlockCommitment>`](strata_asm_worker::Subscription)
//! adapted into a [`StreamInput`](strata_service::StreamInput)). Each emitted
//! commitment is folded into a new [`MohoState`](moho_types::MohoState) and
//! persisted.

use std::marker::PhantomData;

use moho_types::MohoState;
use serde::{Deserialize, Serialize};
use strata_asm_worker::{SyncError, plan_sync};
use strata_identifiers::L1BlockCommitment;
use strata_service::{AsyncService, Response, Service};
use tracing::info;

use crate::{
    MohoWorkerContext, MohoWorkerError, MohoWorkerResult, MohoWorkerServiceState, compute,
};

/// Moho worker service implementation using the service framework.
#[derive(Debug)]
pub struct MohoWorkerService<W> {
    _phantom: PhantomData<W>,
}

impl<W> Service for MohoWorkerService<W>
where
    W: MohoWorkerContext + Send + Sync + 'static,
{
    type State = MohoWorkerServiceState<W>;
    type Msg = L1BlockCommitment;
    type Status = MohoWorkerStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        MohoWorkerStatus {
            is_initialized: true,
            cur_block: Some(state.cur_block()),
            cur_state: Some(state.cur_moho().clone()),
        }
    }
}

impl<W> AsyncService for MohoWorkerService<W>
where
    W: MohoWorkerContext + Send + Sync + 'static,
{
    async fn process_input(
        state: &mut Self::State,
        input: L1BlockCommitment,
    ) -> anyhow::Result<Response> {
        // The store is synchronous (sled), so the fold runs to completion
        // without yielding. A processing error exits the worker — the commit
        // stream cannot be skipped without leaving a gap.
        process_block(state, input)?;
        Ok(Response::Continue)
    }
}

/// Folds a single ASM commit into a new [`MohoState`] and persists it, along
/// with the export-entry leaves its `ExportState` MMR commits to.
///
/// Resolves the commit's parent and chains the Moho state forward onto this
/// block's anchor state and logs. The parent's Moho state comes from the
/// in-memory [`cur_moho`](MohoWorkerServiceState::cur_moho) when the commit
/// builds on the block already held — the in-order common case; otherwise (an L1
/// reorg) it is re-anchored from the parent's committed state in the store.
/// Resolving the real parent rather than assuming height contiguity is what lets
/// the worker follow reorgs.
pub(crate) fn process_block<W: MohoWorkerContext>(
    state: &mut MohoWorkerServiceState<W>,
    block: L1BlockCommitment,
) -> MohoWorkerResult<()> {
    let parent = state.context.get_parent_block(&block)?;

    let parent_moho = if state.cur_block() == parent {
        state.cur_moho().clone()
    } else {
        state.context.get_moho_state(&parent)?
    };

    let anchor_state = state.context.get_anchor_state(&block)?;
    let logs = state.context.get_anchor_logs(&block)?;
    let moho = compute::construct_next_moho_state(&parent_moho, &anchor_state, &logs);

    // Prune this block's height first so a reprocess (crash-replay or reorg)
    // re-stores onto a clean prefix: `store_export_entries` does not dedup, and a
    // single block can contribute several leaves per container, so the suffix is
    // cleared by height rather than popped per block. On forward progress nothing
    // sits at this height yet, so the prune is a no-op.
    state.context.prune_export_entries_from(block.height())?;

    // Persist the export-entry leaves before the Moho state. The worker tracks
    // progress via the Moho store (`get_latest_moho_state`), so `store_moho_state`
    // is this block's commit point: a crash before it leaves progress unadvanced
    // and the block is reprocessed on restart. Writing the leaves after the
    // commit point would risk a gap between them and the `ExportState` MMR that
    // commits to them.
    for (container_id, entries) in compute::export_entries_from_logs(&logs) {
        state
            .context
            .store_export_entries(container_id, block.height(), entries)?;
    }
    state.context.store_moho_state(&block, &moho)?;

    state.update_moho_state(moho, block);

    info!(%block, %parent, "committed Moho state");
    Ok(())
}

/// Catches the Moho store up to the ASM worker's committed tip before the live
/// subscription takes over.
///
/// The ASM worker commits a block's anchor state before the Moho worker folds
/// it, so a crash in that window leaves anchor states with no derived Moho
/// state — the Moho store trails the ASM store. The subscription does not
/// replay, so without this catch-up the next live commit would fold onto a
/// parent whose Moho state is missing and the worker would wedge on
/// [`MissingMohoState`](MohoWorkerError::MissingMohoState).
///
/// The catch-up source is the ASM store itself: every block to fold already has
/// a committed anchor state. It reuses `strata-asm-worker`'s [`plan_sync`] to
/// walk real parents (not heights) back from the ASM tip — staying correct across
/// an L1 reorg during downtime — to the first block already folded (the in-memory
/// `cur_block`, or any block whose Moho state is stored), then folds the gap
/// forward with `process_block`. Genesis is always seeded, so the walk
/// terminates at or above the genesis floor.
///
/// Run once at startup, before the subscription stream is consumed; see
/// [`MohoWorkerBuilder::launch`](crate::MohoWorkerBuilder::launch).
pub fn sync_to_tip<W: MohoWorkerContext>(
    state: &mut MohoWorkerServiceState<W>,
) -> MohoWorkerResult<()> {
    let Some(asm_tip) = state.context.get_latest_asm_block()? else {
        return Ok(());
    };

    // Plan under an immutable borrow of the context; the forward fold below takes
    // `&mut state`, so the borrows must not overlap.
    let plan = {
        let cur_block = state.cur_block();
        let cur_moho = state.cur_moho().clone();
        let ctx = &state.context;
        plan_sync(
            asm_tip,
            state.genesis_height(),
            // The in-memory `cur_block` is the base when the tip builds on it;
            // otherwise look it up in the store. A miss keeps the walk going; any
            // other store error is real and propagates.
            |block| {
                if *block == cur_block {
                    return Ok(Some(cur_moho.clone()));
                }
                match ctx.get_moho_state(block) {
                    Ok(moho) => Ok(Some(moho)),
                    Err(MohoWorkerError::MissingMohoState(_)) => Ok(None),
                    Err(e) => Err(e),
                }
            },
            |block| ctx.get_parent_block(block),
        )
        .map_err(|e| match e {
            SyncError::ReachedFloor { .. } => MohoWorkerError::MissingMohoState(cur_block),
            SyncError::Provider(e) => e,
        })?
    };

    if plan.pending.is_empty() {
        return Ok(());
    }

    // `plan.base_state` is unused: `process_block` re-anchors from each block's
    // parent (in memory or the store), so the fold needs only the block order.
    info!(count = plan.pending.len(), %asm_tip, "syncing Moho state to ASM tip");
    for block in plan.pending.into_iter().rev() {
        process_block(state, block)?;
    }
    Ok(())
}

/// Status information for the Moho worker service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MohoWorkerStatus {
    pub is_initialized: bool,
    pub cur_block: Option<L1BlockCommitment>,
    pub cur_state: Option<MohoState>,
}
