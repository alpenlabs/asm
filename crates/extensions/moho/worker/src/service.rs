//! Service-framework integration for the Moho worker.
//!
//! The worker is an [`AsyncService`] driven by the ASM worker's per-block
//! subscription (a [`Subscription<L1BlockCommitment>`](strata_asm_worker::Subscription)
//! adapted into a [`StreamInput`](strata_service::StreamInput)). Each emitted
//! commitment is folded into a new [`MohoState`](moho_types::MohoState) and
//! persisted, then re-emitted on the worker's own subscription so the prover
//! chains off the Moho commit rather than racing the ASM one.

use std::marker::PhantomData;

use moho_types::MohoState;
use serde::{Deserialize, Serialize};
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
        // The input is the ASM worker's authoritative active tip. Usually it is
        // one child and this folds one block; after a shorter reorg it can be an
        // already-stored ancestor, which must re-anchor rather than be folded as
        // a new child.
        let changed = sync_to_block(state, input)?;

        // Notify subscribers only after the MohoState is durably committed, so
        // any consumer (the prover) that reads it for this block is guaranteed a
        // hit. Mirrors the ASM worker's post-commit fan-out; non-blocking, an
        // unbounded enqueue per subscriber. Startup catch-up (`sync_to_tip`)
        // deliberately does not emit — it runs before any subscriber attaches,
        // and the stream has no replay, matching the ASM commit stream.
        if changed {
            state.subscribers.emit(input);
        }
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
/// a committed anchor state. It walks the ASM and Moho tips back to their common
/// ancestor, then replays the ASM branch even when its Moho states were retained
/// from an earlier visit. That replay is required to rebuild the single
/// height-ordered export-entry index on the selected branch.
///
/// Run once at startup, before the subscription stream is consumed; see
/// [`MohoWorkerBuilder::launch`](crate::MohoWorkerBuilder::launch).
pub fn sync_to_tip<W: MohoWorkerContext>(
    state: &mut MohoWorkerServiceState<W>,
) -> MohoWorkerResult<()> {
    let Some(asm_tip) = state.context.get_latest_asm_block()? else {
        return Ok(());
    };

    sync_to_block(state, asm_tip)?;
    Ok(())
}

/// Adopts `target` as the authoritative ASM tip, replaying its Moho suffix.
///
/// Returns whether the Moho active tip changed. A distinct ancestor target has
/// an empty suffix but still changes the tip: its export-entry suffix is pruned,
/// its retained state becomes active, and downstream receives one re-anchor
/// notification on the live path.
fn sync_to_block<W: MohoWorkerContext>(
    state: &mut MohoWorkerServiceState<W>,
    target: L1BlockCommitment,
) -> MohoWorkerResult<bool> {
    let current = state.cur_block();
    let (base, pending) =
        plan_target_branch(&state.context, target, current, state.genesis_height())?;

    if base == current && pending.is_empty() {
        return Ok(false);
    }

    if base != current {
        let base_moho = state.context.get_moho_state(&base)?;

        // External export-entry leaves are ordered by height rather than block
        // id. Clear the abandoned suffix before the base state becomes the
        // durable commit point. `process_block` repeats the first-height prune,
        // which is intentionally idempotent for crash replay.
        state.context.begin_moho_rebase(&base)?;
        if let Some(first_suffix_height) = base.height().checked_add(1) {
            state
                .context
                .prune_export_entries_from(first_suffix_height)?;
        }
        state.context.finish_moho_rebase(&base)?;
        state.update_moho_state(base_moho, base);
    }

    info!(count = pending.len(), %target, "syncing Moho state to ASM tip");
    for block in pending.into_iter().rev() {
        process_block(state, block)?;
    }
    Ok(true)
}

/// Returns the target-branch suffix above its common ancestor with `current`.
fn plan_target_branch<W: MohoWorkerContext>(
    context: &W,
    target: L1BlockCommitment,
    current: L1BlockCommitment,
    genesis_height: u64,
) -> MohoWorkerResult<(L1BlockCommitment, Vec<L1BlockCommitment>)> {
    let mut target_cursor = target;
    let mut current_cursor = current;
    let mut pending = Vec::new();

    while target_cursor.height() > current_cursor.height() {
        pending.push(target_cursor);
        target_cursor = checked_parent(context, target_cursor, genesis_height, current)?;
    }
    while current_cursor.height() > target_cursor.height() {
        current_cursor = checked_parent(context, current_cursor, genesis_height, current)?;
    }

    while target_cursor != current_cursor {
        pending.push(target_cursor);
        target_cursor = checked_parent(context, target_cursor, genesis_height, current)?;
        current_cursor = checked_parent(context, current_cursor, genesis_height, current)?;
    }

    Ok((target_cursor, pending))
}

fn checked_parent<W: MohoWorkerContext>(
    context: &W,
    block: L1BlockCommitment,
    genesis_height: u64,
    current: L1BlockCommitment,
) -> MohoWorkerResult<L1BlockCommitment> {
    if u64::from(block.height()) <= genesis_height {
        return Err(MohoWorkerError::MissingMohoState(current));
    }
    context.get_parent_block(&block)
}

/// Status information for the Moho worker service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MohoWorkerStatus {
    pub is_initialized: bool,
    pub cur_block: Option<L1BlockCommitment>,
    pub cur_state: Option<MohoState>,
}
