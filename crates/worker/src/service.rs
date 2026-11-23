//! Service framework integration for ASM.

use std::marker;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use strata_asm_common::{AnchorState, AsmHistoryAccumulatorState};
use strata_btc_types::BlockHashExt;
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_service::{Response, Service, SyncService};
use tracing::*;

use crate::{
    AsmWorkerServiceState, SyncError, SyncPlan, WorkerError, message::AsmWorkerMessage, plan_sync,
    traits::WorkerContext,
};

/// ASM service implementation using the service framework.
#[derive(Debug)]
pub struct AsmWorkerService<W> {
    _phantom: marker::PhantomData<W>,
}

impl<W> Service for AsmWorkerService<W>
where
    W: WorkerContext + Send + Sync + 'static,
{
    type State = AsmWorkerServiceState<W>;
    type Msg = AsmWorkerMessage;
    type Status = AsmWorkerStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        AsmWorkerStatus {
            is_initialized: true,
            cur_block: Some(state.blkid),
            cur_state: Some(state.anchor.clone()),
        }
    }
}

impl<W> SyncService for AsmWorkerService<W>
where
    W: WorkerContext + Send + Sync + 'static,
{
    fn process_input(
        state: &mut AsmWorkerServiceState<W>,
        input: AsmWorkerMessage,
    ) -> anyhow::Result<Response> {
        match input {
            AsmWorkerMessage::SubmitBlock(target, completion) => {
                // The wire carries a bitcoin block hash; translate it to the
                // worker's L1 block id at this boundary so nothing downstream
                // deals in bitcoin types.
                match sync_to_block(state, &target.to_l1_block_id()) {
                    Ok(processed) => completion.send_blocking(Ok(processed)),
                    Err(err) => {
                        // A sync error is terminal: nothing will advance ASM state
                        // again, so it is reported as an `Err` rather than
                        // `Response::ShouldExit`. The framework turns an `Err` into
                        // a critical-task failure, which the host can act on. A
                        // clean exit is indistinguishable from the worker finishing
                        // its work, so it tells the host nothing.
                        //
                        // Log the failure here as well. The caller's completion
                        // result may be awaited on another task, and `WorkerError`
                        // is not `Clone`, so the caller gets the typed error and
                        // the task exits with a rendering of it.
                        error!(%target, %err, "ASM sync failed; shutting down worker");
                        let fatal = anyhow!("ASM sync failed for block {target}: {err}");
                        completion.send_blocking(Err(err));
                        return Err(fatal);
                    }
                }
            }
        }
        Ok(Response::Continue)
    }
}

/// Synchronizes the ASM state up to the submitted block, processing every L1
/// block between the last already-processed ancestor and the target.
///
/// The caller submits only an id; the worker resolves its height from the L1
/// source once (see
/// [`get_l1_block_height`](crate::L1DataProvider::get_l1_block_height)) to form
/// the target commitment, then derives every later height itself.
///
/// `target` is a block submitted to the worker; it may extend the current chain
/// or, on an L1 reorg, switch to a different branch (even one whose tip is at a
/// lower height). Runs in three phases:
///
/// 1. **Plan** (backward): from `target`, follow parent links via each block's `prev_blockhash`
///    back to the base — the most recent ancestor with a stored `AnchorState` — collecting the
///    unprocessed blocks in between. This walks `target`'s own ancestry, so on an L1 reorg the base
///    is the fork point and the abandoned branch is never visited. Only block headers are read
///    here, so a deep reorg does not load every intervening block into memory at once. See
///    [`plan_block_processing`].
///
/// 2. **Repair**: make the stored manifest MMR match the base's accumulator. The MMR is keyed by
///    height, so when the base is a block the worker left on an earlier reorg, the leaves at and
///    below it may still hold the abandoned branch's hashes. See [`repair_manifest_mmr`].
///
/// 3. **Process** (forward): from the base forward (oldest first, so heights are contiguous and
///    strictly increasing), fetch each full block, run the STF, then persist its manifest into the
///    height-indexed MMR, its aux data, and its anchor state, advancing the in-memory anchor as it
///    goes. Processing a height already handled on the old branch overwrites that branch's leaf in
///    place, which is why the manifest MMR supports leaf replacement. See [`apply_block`].
///
/// When `target` already has a stored anchor the plan has no blocks to apply: it
/// has been processed before. That is a duplicate or lagging notification, not a
/// reorg (a genuine reorg always carries at least one new block on the new
/// branch), so the worker leaves its tip untouched and returns without writing.
///
/// Returns the commitments processed, oldest first — possibly several blocks for
/// one submit, or empty when the target is already processed or before genesis.
///
/// A `target` before genesis is ignored (returns `Ok`). If the backward walk
/// descends below genesis without finding a stored anchor state, returns
/// `WorkerError::MissingGenesisState`. Any fetch, transition, or storage error
/// is propagated; the caller treats it as fatal and shuts the worker down.
fn sync_to_block<W>(
    state: &mut AsmWorkerServiceState<W>,
    target_blkid: &L1BlockId,
) -> crate::WorkerResult<Vec<L1BlockCommitment>>
where
    W: WorkerContext + Send + Sync + 'static,
{
    // Resolve the submitted id to a height-tagged commitment. This is the only
    // height the worker takes from outside; every later height is derived from
    // the parent chain as the STF processes each block.
    let genesis_height = state.genesis_height();
    let height = state.context.get_l1_block_height(target_blkid)?;
    let target = L1BlockCommitment::new(height, *target_blkid);

    // Ignore blocks before genesis. Compared in the wider domain because
    // `genesis_height` is an MMR leaf index, which is a `u64`.
    if u64::from(height) < genesis_height {
        warn!(height, "ignoring unexpected L1 block before genesis");
        return Ok(vec![]);
    }

    // Phase 1: plan the work — the base state and the blocks to process onto it.
    let plan_span = debug_span!("asm.processing_plan",
        target_height = height,
        target_block = %target.blkid()
    );
    let plan_span_guard = plan_span.enter();

    let SyncPlan {
        base_state,
        base_block,
        pending,
    } = plan_block_processing(&state.context, &target, genesis_height)?;

    info!(%base_block,
        pending_blocks = pending.len(),
        "ASM found processing base"
    );
    drop(plan_span_guard);

    // An empty plan means `target` already has a stored anchor: it has been
    // processed before, and there is no new work. So return early.
    if pending.is_empty() {
        warn!(
            %target,
            tip = %state.blkid,
            "block already processed; ignoring duplicate or stale notification"
        );
        return Ok(vec![]);
    }

    // A non-empty plan whose base isn't the current in-memory tip is a genuine
    // reorg: the backward walk followed `target`'s ancestry to a fork point
    // below the tip, so the prior branch's blocks above the fork are abandoned
    // and rewritten in place by the forward pass below.
    if base_block != state.blkid {
        warn!(
            old_tip = %state.blkid,
            fork_point = %base_block,
            new_target = %target,
            abandoned_blocks = state.blkid.height().saturating_sub(base_block.height()),
            "ASM L1 reorg detected"
        );
    }

    // Phase 2: repair the leaves the base's accumulator commits to. This also
    // runs when the base is the in-memory tip. After a restart that tip is only
    // the highest stored anchor, and another branch may have overwritten its
    // leaves since.
    repair_manifest_mmr(&state.context, &base_state, base_block, genesis_height)?;

    state.restore_anchor(base_state, base_block)?;

    // Phase 3: process the pending blocks oldest first. Collect them in applied
    // order so the caller can drive per-block follow-up work (e.g. proof
    // requests) over exactly the blocks the worker processed for this submit.
    let processed: Vec<L1BlockCommitment> = pending.into_iter().rev().collect();
    for block_id in &processed {
        let transition_span = debug_span!("asm.block_transition",
            height = block_id.height(),
            block_id = %block_id.blkid()
        );
        let _transition_guard = transition_span.enter();

        info!(%block_id, "ASM transition attempt");
        apply_block(state, block_id)?;
        info!(%block_id, "ASM transition complete, manifest and state stored");
    }

    Ok(processed)
}

/// Walks back from `target` along parent links to build a
/// [`SyncPlan<AnchorState>`]: the base — the most recent ancestor with a stored
/// anchor state — and the unprocessed blocks between it and `target`.
///
/// A thin adapter over [`plan_sync`]: the base is a stored anchor state, and
/// parents are resolved by reading only each block's header (its
/// `prev_blockhash`), so a deep reorg does not load every intervening block into
/// memory — the full block is fetched per-height during the forward pass. Errors
/// with [`MissingGenesisState`](crate::WorkerError::MissingGenesisState) if the
/// walk reaches genesis without finding a stored anchor.
fn plan_block_processing<W: WorkerContext>(
    ctx: &W,
    target: &L1BlockCommitment,
    genesis_height: u64,
) -> crate::WorkerResult<SyncPlan<AnchorState>> {
    plan_sync(
        *target,
        genesis_height,
        // A miss is "not a base, keep walking"; any other store error is real
        // and propagates rather than being mistaken for an unprocessed block.
        |block| match ctx.get_anchor_state(block) {
            Ok(anchor) => Ok(Some(anchor)),
            Err(WorkerError::MissingAsmState(_)) => Ok(None),
            Err(e) => Err(e),
        },
        |block| parent_block(ctx, block),
    )
    .map_err(|e| match e {
        SyncError::ReachedFloor { .. } => {
            error!(%target, genesis_height, "ASM hasn't found base anchor state at genesis");
            WorkerError::MissingGenesisState
        }
        SyncError::Provider(e) => e,
    })
}

/// Resolves the parent of `block` by reading only its header.
fn parent_block<W: WorkerContext>(
    ctx: &W,
    block: &L1BlockCommitment,
) -> crate::WorkerResult<L1BlockCommitment> {
    let header = ctx.get_l1_block_header(block.blkid())?;
    Ok(L1BlockCommitment::new(
        block.height() - 1,
        header.prev_blockhash.to_l1_block_id(),
    ))
}

/// Makes the stored manifest MMR match `base_state`'s accumulator before any
/// block is applied on top of `base_block`.
///
/// The MMR is keyed by height, so each branch the worker processes overwrites
/// the leaves at its heights. Take a node that processes block A, then reorgs
/// to B at the same height, then back to A's branch. The plan stops at A
/// because its anchor is stored, but leaf `A.height` still holds B's hash. Aux
/// resolution would then build manifest proofs that fail against A's
/// accumulator, and the worker would halt on every restart.
///
/// Walks back from `base_block` and re-records each stale leaf from the
/// block's stored manifest until the MMR matches. On forward progress and on
/// most reorgs it already matches, so this only reads. Each rewrite is an
/// idempotent overwrite, so a crash partway through is finished by the next
/// sync.
fn repair_manifest_mmr<W: WorkerContext>(
    ctx: &W,
    base_state: &AnchorState,
    base_block: L1BlockCommitment,
    genesis_height: u64,
) -> crate::WorkerResult<()> {
    let accumulator = &base_state.chain_view.history_accumulator;
    let mut block = base_block;
    let mut rewritten = 0u32;
    while !manifest_mmr_matches(ctx, accumulator, genesis_height)? {
        // Leaves at and below genesis are seeded peaks that no branch can
        // overwrite, so a mismatch that survives down to genesis is not a
        // stale branch.
        if u64::from(block.height()) <= genesis_height {
            return Err(WorkerError::ManifestMmrMismatch(base_block));
        }
        // Rewrite stale leaves down to the first one that already holds the
        // right hash, then check the whole MMR again. A reorg to a shorter
        // branch can leave more stale leaves below a correct one.
        loop {
            let height = u64::from(block.height());
            let hash = ctx.get_manifest(&block)?.compute_hash();
            let stale = ctx.get_manifest_hash(height)? != hash;
            if stale {
                ctx.put_manifest_hash(height, hash)?;
                rewritten += 1;
            }
            block = parent_block(ctx, &block)?;
            if !stale || u64::from(block.height()) <= genesis_height {
                break;
            }
        }
    }

    if rewritten > 0 {
        info!(
            %base_block,
            rewritten,
            "rewrote manifest MMR leaves left by an abandoned branch"
        );
    }
    Ok(())
}

/// Whether the stored manifest MMR, cut to the accumulator's size, has the
/// accumulator's peaks.
///
/// Proves the last leaf of each mountain from storage and verifies it against
/// the accumulator. The stored path hashes up to the stored peak, so this
/// checks every leaf under it. Mountains that end at or below genesis are
/// skipped: their peaks were seeded from the genesis accumulator, and nothing
/// can overwrite them.
fn manifest_mmr_matches<W: WorkerContext>(
    ctx: &W,
    accumulator: &AsmHistoryAccumulatorState,
    genesis_height: u64,
) -> crate::WorkerResult<bool> {
    let leaf_count = accumulator.num_entries();
    let mut mountain_start = 0u64;
    for bit in (0..u64::BITS).rev() {
        let size = 1u64 << bit;
        if leaf_count & size == 0 {
            continue;
        }
        let last_leaf = mountain_start + size - 1;
        mountain_start += size;
        if last_leaf <= genesis_height {
            continue;
        }
        let hash = ctx.get_manifest_hash(last_leaf)?;
        let proof = ctx.generate_mmr_proof_at(last_leaf, leaf_count)?;
        if !accumulator.verify_manifest_leaf(&proof, &hash) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Runs the STF for `block_id`, then persists the results in a deliberate
/// order — the manifest (into the height-indexed MMR) and the prover aux data
/// first, the anchor state last — before advancing the in-memory anchor.
///
/// The order is the crash-safety contract. The anchor state is this block's
/// commit point: [`plan_block_processing`] treats a block as processed only
/// once its anchor state is stored, so it is written after everything derived
/// from the block. If an error aborts after the manifest or aux data write but
/// before the anchor state, the block stays uncommitted and the next sync
/// re-runs its STF. That re-run is safe: every write on this path is an
/// idempotent, block-keyed overwrite (the MMR leaf is replaced by height, aux
/// data and anchor state are keyed by block id, and the STF is deterministic,
/// so it reproduces identical values.
fn apply_block<W>(
    state: &mut AsmWorkerServiceState<W>,
    block_id: &L1BlockCommitment,
) -> crate::WorkerResult<()>
where
    W: WorkerContext + Send + Sync + 'static,
{
    // Fetch the full block now, one height at a time, so only a single block is
    // resident at any point during the forward pass.
    let block = state.context.get_l1_block(block_id.blkid())?;
    let (asm_stf_out, aux_data) = state.transition(&block)?;

    // Persist the manifest and record its hash in the height-indexed MMR.
    state
        .context
        .record_manifest(asm_stf_out.manifest.clone())?;
    // Store auxiliary data for prover consumption.
    state.context.store_aux_data(block_id, &aux_data)?;

    // Anchor state last: it is the block's commit point (see fn docs), so a
    // crash before it leaves the block uncommitted to be safely re-run. The
    // STF's logs are already persisted in the manifest recorded above.
    state.context.store_anchor_state(&asm_stf_out.state)?;
    state.accept_output(asm_stf_out, *block_id);

    // Notify subscribers only after the anchor is durably committed, so any
    // consumer that reads `AsmStateDb` for this commitment is guaranteed a
    // hit. Non-blocking: an unbounded fan-out, never awaited.
    state.subscribers.emit(*block_id);

    Ok(())
}

/// Status information for the ASM worker service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AsmWorkerStatus {
    pub is_initialized: bool,
    pub cur_block: Option<L1BlockCommitment>,
    pub cur_state: Option<AnchorState>,
}

#[cfg(test)]
mod tests {
    use std::thread;

    use bitcoind_async_client::traits::Reader;
    use strata_asm_common::AuxRequestCollector;
    use strata_btc_types::L1BlockIdBitcoinExt;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_service::CommandCompletionSender;
    use tokio::{sync::oneshot, task::block_in_place};

    use super::*;
    use crate::{
        AnchorStateStore, AuxDataResolver, ManifestMmrStore, WorkerError,
        test_utils::{TestAsmWorkerContext, fixtures},
    };

    /// Leaf count of the accumulator carried by the current in-memory anchor —
    /// the snapshot size [`AsmWorkerServiceState::transition`] resolves aux data
    /// against.
    fn anchor_leaf_count(state: &AsmWorkerServiceState<TestAsmWorkerContext>) -> u64 {
        state.anchor.chain_view.history_accumulator.num_entries()
    }

    /// Pending block heights in the order they're processed (oldest first).
    ///
    /// `plan.pending` is stored newest-first; reversing here keeps the test
    /// expectations ascending, which is easier to read.
    fn pending_heights(plan: &SyncPlan<AnchorState>) -> Vec<u32> {
        plan.pending.iter().rev().map(|b| b.height()).collect()
    }

    /// A target extending the stored chain: the base is the genesis anchor and
    /// every block above it is pending, applied oldest first.
    #[tokio::test(flavor = "multi_thread")]
    async fn plan_linear_extension() {
        let fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 3).await; // 102, 103, 104
        let target = *mined.last().unwrap();

        let plan = plan_block_processing(&fx.state.context, &target, fx.state.genesis_height())
            .expect("plan should succeed");

        assert_eq!(plan.base_block, fx.state.blkid);
        assert_eq!(plan.base_state, fx.state.anchor);
        assert_eq!(pending_heights(&plan), vec![102, 103, 104]);
    }

    /// A target that already has a stored anchor is its own base, with nothing
    /// left to process.
    #[tokio::test(flavor = "multi_thread")]
    async fn plan_target_already_processed() {
        let mut fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 2).await; // 102, 103
        let target = mined[0]; // 102

        // Process 102 for real so it has a stored anchor.
        sync_to_block(&mut fx.state, target.blkid()).expect("process 102");

        let plan = plan_block_processing(&fx.state.context, &target, fx.state.genesis_height())
            .expect("plan should succeed");

        assert_eq!(plan.base_block, target);
        assert!(plan.pending.is_empty());
    }

    /// On an L1 reorg, planning walks the *target's* ancestry, so the base is
    /// the fork point — even though the abandoned branch's tip still has a
    /// stored anchor — and the abandoned blocks are never visited.
    #[tokio::test(flavor = "multi_thread")]
    async fn plan_reorg_uses_fork_point() {
        let mut fx = fixtures::setup_state(101).await;

        // Branch A, fully processed: 102 (the eventual fork point) and 103a.
        let fork_point = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 102
        let old_tip = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 103a
        sync_to_block(&mut fx.state, old_tip.blkid()).expect("process branch A");

        // Reorg away 103a and mine a longer branch B: 103b, 104b.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, old_tip.height() as u64, 2).await;
        let new_tip = *branch_b.last().unwrap(); // 104b

        let plan = plan_block_processing(&fx.state.context, &new_tip, fx.state.genesis_height())
            .expect("plan should succeed");

        assert_eq!(plan.base_block, fork_point);
        assert!(!plan.pending.contains(&old_tip));
        assert_eq!(pending_heights(&plan), vec![103, 104]);
    }

    /// When the backward walk reaches the genesis floor without finding a stored
    /// anchor, planning fails with `MissingGenesisState`.
    #[tokio::test(flavor = "multi_thread")]
    async fn plan_missing_genesis_state() {
        let fx = fixtures::setup_context(104).await;
        let tip = fx.client.get_block_hash(104).await.unwrap();
        let target = L1BlockCommitment::new(104, tip.to_l1_block_id());

        let result = plan_block_processing(&fx.context, &target, 101);

        assert!(
            matches!(result, Err(WorkerError::MissingGenesisState)),
            "expected MissingGenesisState",
        );
    }

    /// A target below the genesis height is ignored: no error, no state change.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_before_genesis_ignored() {
        let mut fx = fixtures::setup_state(101).await;
        let genesis = fx.state.blkid;
        let leaves_before = fx.state.context.mmr_leaf_count();

        let below = fx
            .client
            .get_block_hash(100)
            .await
            .unwrap()
            .to_l1_block_id();

        let processed = sync_to_block(&mut fx.state, &below)
            .expect("pre-genesis target is ignored, not an error");

        assert!(processed.is_empty(), "nothing processed before genesis");
        assert_eq!(fx.state.blkid, genesis, "anchor must not move");
        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            leaves_before,
            "nothing stored",
        );
    }

    /// Syncing a chain extension processes every block above the base: the anchor
    /// reaches the target, each height gets a stored anchor state, and one
    /// manifest leaf lands per height.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_linear_advances_anchor() {
        let mut fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 3).await; // 102, 103, 104
        let target = *mined.last().unwrap();

        let processed = sync_to_block(&mut fx.state, target.blkid()).expect("sync should succeed");

        assert_eq!(
            processed, mined,
            "returns every processed block, oldest first"
        );
        assert_eq!(fx.state.blkid, target, "anchor advanced to target");
        for blk in &mined {
            assert!(
                fx.state.context.get_anchor_state(blk).is_ok(),
                "anchor stored for {blk}",
            );
        }
        // Genesis prefix 0..=101 (102 leaves) plus one manifest per processed height.
        assert_eq!(fx.state.context.mmr_leaf_count(), 105);
    }

    /// Re-submitting an already-processed block — a duplicate or lagging ZMQ
    /// notification for an ancestor of the current tip — is a no-op: it processes
    /// nothing, leaves the in-memory tip where it was, and writes nothing.
    /// Rolling the tip back here is the phantom reorg that corrupted derived
    /// state (see `sync_to_block`).
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_duplicate_already_processed_block_is_noop() {
        let mut fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 2).await; // 102, 103
        let earlier = mined[0];
        let tip = mined[1];

        sync_to_block(&mut fx.state, tip.blkid()).expect("initial sync");
        let leaves_after_sync = fx.state.context.mmr_leaf_count();
        assert_eq!(fx.state.blkid, tip);

        let processed = sync_to_block(&mut fx.state, earlier.blkid()).expect("resync");

        assert!(
            processed.is_empty(),
            "an already-processed target applies nothing",
        );
        assert_eq!(
            fx.state.blkid, tip,
            "the tip stays put — a stale notification must not roll it back",
        );
        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            leaves_after_sync,
            "no reprocessing: leaf count unchanged",
        );
    }

    /// A duplicate or stale notification for an already-processed ancestor must
    /// not disturb the durable `latest` pointer: it stays on the real tip, so a
    /// restart resumes there rather than rolling back to the re-delivered block.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_stale_notification_keeps_latest_at_tip() {
        let mut fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 2).await; // 102, 103
        let earlier = mined[0];
        let tip = mined[1];

        sync_to_block(&mut fx.state, tip.blkid()).expect("initial sync");
        assert_eq!(
            fx.state
                .context
                .get_latest_anchor_state()
                .unwrap()
                .map(|s| s.last_processed_block()),
            Some(tip),
            "latest tracks the tip after the initial sync",
        );

        sync_to_block(&mut fx.state, earlier.blkid()).expect("resync to the earlier block");

        // The durable pointer is unmoved by the stale notification...
        assert_eq!(
            fx.state
                .context
                .get_latest_anchor_state()
                .unwrap()
                .map(|s| s.last_processed_block()),
            Some(tip),
            "latest stays at the real tip",
        );

        // ...so a restart over the same store resumes at the tip.
        let context = fx.state.context.clone();
        let params = fixtures::genesis_params(&fx.client, 101).await;
        let reloaded = fixtures::new_state(context, params).unwrap();
        assert_eq!(
            reloaded.blkid, tip,
            "restart resumes from the tip, not the stale notification",
        );
    }

    /// On a reorg, the heights shared with the old branch have their manifest
    /// leaves overwritten in place (not appended), while the common fork point
    /// below the divergence is left untouched.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_reorg_overwrites_leaves() {
        let mut fx = fixtures::setup_state(101).await;

        // Branch A: process 102, 103, 104.
        let branch_a = fixtures::mine(&fx.node, &fx.client, 3).await;
        sync_to_block(&mut fx.state, branch_a.last().unwrap().blkid()).expect("sync branch A");
        let leaf_a_102 = fx
            .state
            .context
            .get_manifest_hash(102)
            .expect("leaf 102 on A");
        let leaf_a_103 = fx
            .state
            .context
            .get_manifest_hash(103)
            .expect("leaf 103 on A");

        // Reorg below 103 and process a longer branch B: 103b, 104b, 105b.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, 103, 3).await;
        let new_tip = *branch_b.last().unwrap();
        sync_to_block(&mut fx.state, new_tip.blkid()).expect("sync branch B");

        assert_eq!(fx.state.blkid, new_tip, "anchor on the new branch");
        // Heights 103, 104 overwritten in place; 105 appended — not 108 leaves.
        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            106,
            "overwrite, not append"
        );
        assert_ne!(
            fx.state
                .context
                .get_manifest_hash(103)
                .expect("leaf 103 on B"),
            leaf_a_103,
            "leaf 103 now reflects branch B",
        );
        assert_eq!(
            fx.state
                .context
                .get_manifest_hash(102)
                .expect("leaf 102 on B"),
            leaf_a_102,
            "the fork point is untouched",
        );
    }

    /// A reorg back onto a branch the worker already processed. A at 103 is
    /// processed, then B overwrites leaf 103, then A's branch wins again. The
    /// plan stops at A because its anchor is stored, so the forward pass never
    /// touches leaf 103. The repair must rewrite it, or manifest proofs built
    /// from storage fail against the anchor's accumulator.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_reorg_back_to_processed_branch_rewrites_stale_leaves() {
        let mut fx = fixtures::setup_state(101).await;

        // Branch A: 102, 103.
        let branch_a = fixtures::mine(&fx.node, &fx.client, 2).await;
        let a_103 = branch_a[1];
        sync_to_block(&mut fx.state, a_103.blkid()).expect("sync branch A");
        let leaf_a_103 = fx
            .state
            .context
            .get_manifest_hash(103)
            .expect("leaf 103 on A");

        // Branch B forks below 103 and overwrites leaf 103.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, 103, 2).await; // 103b, 104b
        sync_to_block(&mut fx.state, branch_b[1].blkid()).expect("sync branch B");
        assert_ne!(
            fx.state
                .context
                .get_manifest_hash(103)
                .expect("leaf 103 on B"),
            leaf_a_103,
        );

        // Back to A: restore 103, drop B, and extend A to 105.
        fx.node
            .client
            .reconsider_block(a_103.blkid().to_block_hash())
            .expect("reconsider A");
        fx.node
            .client
            .invalidate_block(branch_b[0].blkid().to_block_hash())
            .expect("invalidate B");
        let extension = fixtures::mine(&fx.node, &fx.client, 2).await; // 104, 105
        let processed = sync_to_block(&mut fx.state, extension[1].blkid()).expect("sync back to A");
        assert_eq!(
            processed, extension,
            "the plan starts from the stored A at 103"
        );

        assert_eq!(
            fx.state.context.get_manifest_hash(103).expect("leaf 103"),
            leaf_a_103,
            "leaf 103 holds A's hash again",
        );

        assert_leaves_prove(&fx.state, 102, 105);
    }

    /// Like the test above, but the stale leaf sits below correct ones. A
    /// reorg to the shorter branch B rewrites only leaf 103, so after the
    /// return to A, leaves 104 and 105 already hold A's hashes and 103 does
    /// not. The repair must not stop at the first correct leaf.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_reorg_back_rewrites_stale_leaf_below_correct_ones() {
        let mut fx = fixtures::setup_state(101).await;

        // Branch A: 102..=105.
        let branch_a = fixtures::mine(&fx.node, &fx.client, 4).await;
        sync_to_block(&mut fx.state, branch_a[3].blkid()).expect("sync branch A");

        // Shorter branch B: only 103b.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, 103, 1).await;
        sync_to_block(&mut fx.state, branch_b[0].blkid()).expect("sync branch B");

        // Back to A and extend it to 106.
        fx.node
            .client
            .reconsider_block(branch_a[1].blkid().to_block_hash())
            .expect("reconsider A");
        fx.node
            .client
            .invalidate_block(branch_b[0].blkid().to_block_hash())
            .expect("invalidate B");
        let extension = fixtures::mine(&fx.node, &fx.client, 1).await; // 106
        sync_to_block(&mut fx.state, extension[0].blkid()).expect("sync back to A");

        assert_leaves_prove(&fx.state, 102, 106);
    }

    /// A restart after a reorg onto a shorter branch, which we accept rather
    /// than fix (STR-3819). The taller orphan is still the store's `latest`,
    /// so a restart resumes on it, and the startup submit of the stored
    /// canonical tip does nothing. Each new canonical block re-anchors on its
    /// real parent, so the orphan never feeds a transition. Restarts keep
    /// resuming on the orphan until the canonical branch out-heights it.
    #[tokio::test(flavor = "multi_thread")]
    async fn restart_after_short_reorg_resumes_on_orphan() {
        let mut fx = fixtures::setup_state(101).await;
        let client = fx.client.clone();
        let restart = async |context: &TestAsmWorkerContext| {
            let params = fixtures::genesis_params(&client, 101).await;
            fixtures::new_state(context.clone(), params).unwrap()
        };

        // Branch A: 102..=105.
        let branch_a = fixtures::mine(&fx.node, &fx.client, 4).await;
        let orphan_tip = branch_a[3];
        sync_to_block(&mut fx.state, orphan_tip.blkid()).expect("sync branch A");

        // Shorter branch B: only 103b.
        let b_103 = fixtures::reorg(&fx.node, &fx.client, 103, 1).await[0];
        sync_to_block(&mut fx.state, b_103.blkid()).expect("sync branch B");

        let mut state = restart(&fx.state.context).await;
        assert_eq!(state.blkid, orphan_tip, "restart resumes on the orphan");
        let processed = sync_to_block(&mut state, b_103.blkid()).expect("startup submit");
        assert!(processed.is_empty(), "103b is already stored");
        assert_eq!(state.blkid, orphan_tip);

        // 104b is still below the orphan, but it re-anchors on its real parent.
        let b_104 = fixtures::mine(&fx.node, &fx.client, 1).await[0];
        let processed = sync_to_block(&mut state, b_104.blkid()).expect("sync 104b");
        assert_eq!(processed, vec![b_104]);
        assert_eq!(state.blkid, b_104);
        assert_leaves_prove(&state, 102, 104);

        // The orphan still out-heights B, so the next restart resumes on it too.
        let mut state = restart(&state.context).await;
        assert_eq!(state.blkid, orphan_tip);

        // 106b out-heights the orphan, so a restart finally resumes on B.
        let b_106 = fixtures::mine(&fx.node, &fx.client, 2).await[1];
        sync_to_block(&mut state, b_106.blkid()).expect("sync 106b");
        let state = restart(&state.context).await;
        assert_eq!(state.blkid, b_106);
        assert_leaves_prove(&state, 102, 106);
    }

    /// Asserts that every leaf in `start..=end` resolves from storage with a
    /// proof that verifies against the current anchor's accumulator.
    fn assert_leaves_prove(
        state: &AsmWorkerServiceState<TestAsmWorkerContext>,
        start: u64,
        end: u64,
    ) {
        let leaf_count = anchor_leaf_count(state);
        let resolver = AuxDataResolver::new(&state.context, leaf_count);
        let mut req = AuxRequestCollector::new(leaf_count);
        req.request_manifest_hashes(start, end);
        let data = resolver
            .resolve(&req.into_requests())
            .expect("resolve manifest hashes");
        assert_eq!(data.manifest_hashes().len() as u64, end - start + 1);
        let accumulator = &state.anchor.chain_view.history_accumulator;
        for item in data.manifest_hashes() {
            assert!(accumulator.verify_manifest_leaf(item.proof(), item.hash()));
        }
    }

    /// End-to-end at the resolver boundary: drive the real STF over a chain,
    /// then reorg to a shorter branch and probe what the post-reorg context can
    /// serve to a prover.
    ///
    /// Genesis at height 5. Chain A (6,7,8,9) is fully processed, so every
    /// height 6..=9 resolves against the anchor-9 accumulator. Reorging to the
    /// shorter branch B (6',7') overwrites heights 6,7 in place but leaves the
    /// now-orphaned 8,9 sitting in storage. The point: those orphans are still
    /// *present* (their hashes are fetchable) yet no longer *provable* — an
    /// inclusion proof can't be built against the shorter post-reorg accumulator,
    /// so the resolver refuses them. They stay until 8',9' overwrite them.
    #[tokio::test(flavor = "multi_thread")]
    async fn reorg_orphans_leaves_present_but_unprovable() {
        let mut fx = fixtures::setup_state(5).await;

        // Chain A: process 6, 7, 8, 9 through the full STF.
        let branch_a = fixtures::mine(&fx.node, &fx.client, 4).await; // 6,7,8,9
        let tip_a = *branch_a.last().unwrap(); // 9
        sync_to_block(&mut fx.state, tip_a.blkid()).expect("sync branch A");
        assert_eq!(fx.state.blkid, tip_a, "anchor at chain A tip");

        // The resolver runs against the current anchor's accumulator: genesis
        // prefix 0..=5 plus one manifest per processed height 6..=9.
        let leaf_count_a = anchor_leaf_count(&fx.state);
        assert_eq!(leaf_count_a, 10);

        // Everything up to height 9 resolves against chain A.
        let resolver_a = AuxDataResolver::new(&fx.state.context, leaf_count_a);
        let mut req_a = AuxRequestCollector::new(leaf_count_a);
        req_a.request_manifest_hashes(6, 9);
        let data = resolver_a
            .resolve(&req_a.into_requests())
            .expect("resolve 6..=9 on chain A");
        assert_eq!(
            data.manifest_hashes().len(),
            4,
            "one entry per height 6..=9"
        );

        // Snapshot the specific chain-A leaves this test compares after the reorg.
        let leaf_a_6 = fx.state.context.get_manifest_hash(6).expect("leaf 6 on A");
        let leaf_a_8 = fx.state.context.get_manifest_hash(8).expect("leaf 8 on A");
        let leaf_a_9 = fx.state.context.get_manifest_hash(9).expect("leaf 9 on A");

        // Reorg: invalidate 6 (drops 6..=9), mine a *shorter* branch B: 6', 7'.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, 6, 2).await; // 6',7'
        let tip_b = *branch_b.last().unwrap(); // 7'
        sync_to_block(&mut fx.state, tip_b.blkid()).expect("sync branch B");
        assert_eq!(fx.state.blkid, tip_b, "anchor on branch B");

        // (1) The orphaned leaves 8,9 are still in storage — branch B only
        // reached height 7, so it never touched them. The leaf count is
        // unchanged and the hashes still hold chain A's values.
        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            10,
            "8,9 still occupy the MMR",
        );
        for (height, chain_a_hash) in [(8u64, leaf_a_8), (9u64, leaf_a_9)] {
            let hash = fx
                .state
                .context
                .get_manifest_hash(height)
                .expect("orphaned hash still fetchable");
            assert_eq!(
                hash, chain_a_hash,
                "leaf {height} still holds chain A's hash",
            );
        }
        // Heights 6,7 were overwritten in place by branch B.
        assert_ne!(
            fx.state.context.get_manifest_hash(6).expect("leaf 6 on B"),
            leaf_a_6,
            "leaf 6 now reflects branch B",
        );

        // The post-reorg accumulator is shorter: genesis prefix 0..=5 plus 6',7'.
        let leaf_count_b = anchor_leaf_count(&fx.state);
        assert_eq!(leaf_count_b, 8, "snapshot shrank to branch B's length");
        let resolver_b = AuxDataResolver::new(&fx.state.context, leaf_count_b);

        // Branch B's own heights still resolve.
        let mut req_b = AuxRequestCollector::new(leaf_count_b);
        req_b.request_manifest_hashes(6, 7);
        resolver_b
            .resolve(&req_b.into_requests())
            .expect("6'..=7' resolve on branch B");

        // (2) But the orphaned 8,9 can't be proven against the shorter snapshot:
        // their index sits at/over the snapshot leaf count, so proof generation
        // fails at the first such index (8). The collector would normally drop
        // such a request as out-of-bounds, so bypass that clamp to exercise the
        // resolver-level guarantee directly.
        let mut req_orphans = AuxRequestCollector::new(u64::MAX);
        req_orphans.request_manifest_hashes(8, 9);
        let result = resolver_b.resolve(&req_orphans.into_requests());
        assert!(
            matches!(result, Err(WorkerError::MmrProofFailed { index: 8 })),
            "orphaned leaves are present but unprovable at the post-reorg snapshot",
        );
    }

    /// A fetch failure resolving the submitted id (a block the node cannot
    /// serve) propagates out of `sync_to_block` rather than being swallowed —
    /// here at the up-front height lookup, before any walk.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_propagates_fetch_error() {
        let mut fx = fixtures::setup_state(101).await;
        // Not a real block, so resolving its height to form the target
        // commitment fails.
        let bogus = L1BlockId::from(Buf32::from([0xab; 32]));

        let result = sync_to_block(&mut fx.state, &bogus);

        assert!(matches!(result, Err(WorkerError::MissingL1Block(_))));
    }

    /// `apply_block` runs the STF for a single block, records its manifest, and
    /// advances the in-memory anchor.
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_block_stores_manifest_and_advances() {
        let mut fx = fixtures::setup_state(101).await;
        let block = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 102, child of genesis

        apply_block(&mut fx.state, &block).expect("apply_block should succeed");

        assert_eq!(fx.state.blkid, block, "in-memory anchor advanced");
        assert!(
            fx.state.context.get_anchor_state(&block).is_ok(),
            "anchor persisted",
        );
        // Genesis prefix 0..=101 (102 leaves) plus the one manifest just recorded.
        assert_eq!(fx.state.context.mmr_leaf_count(), 103);
    }

    /// Re-running `apply_block` for the same block reproduces identical results
    /// and overwrites in place — the idempotency the crash-safety contract leans
    /// on when a sync re-runs an uncommitted block.
    #[tokio::test(flavor = "multi_thread")]
    async fn apply_block_rerun_is_idempotent() {
        let mut fx = fixtures::setup_state(101).await;
        let genesis_state = fx.state.anchor.clone();
        let genesis_blk = fx.state.blkid;
        let block = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 102

        apply_block(&mut fx.state, &block).expect("first apply");
        let first_leaf = fx.state.context.get_manifest_hash(102).expect("leaf 102");
        let first_state = fx.state.context.get_anchor_state(&block).unwrap();
        let first_count = fx.state.context.mmr_leaf_count();

        // Rewind the in-memory anchor to the parent (as a crash before the
        // anchor-state commit would leave it) and re-run the block.
        fx.state.update_anchor_state(genesis_state, genesis_blk);
        apply_block(&mut fx.state, &block).expect("re-apply");

        assert_eq!(
            fx.state.context.get_manifest_hash(102).expect("leaf 102"),
            first_leaf,
            "manifest reproduced",
        );
        assert_eq!(
            fx.state.context.get_anchor_state(&block).unwrap(),
            first_state,
            "anchor reproduced",
        );
        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            first_count,
            "overwrite, no extra append",
        );
    }

    /// Runs `process_input` the way the service framework does — on a plain OS
    /// thread off the async runtime. `send_blocking` (and any block fetch the
    /// context drives via its captured handle) panic in an async context, so the
    /// dedicated thread is load-bearing, not incidental. `block_in_place` keeps
    /// the runtime free to serve that fetch while this thread blocks on it.
    fn process_input_off_runtime(
        mut state: AsmWorkerServiceState<TestAsmWorkerContext>,
        msg: AsmWorkerMessage,
    ) -> (
        anyhow::Result<Response>,
        AsmWorkerServiceState<TestAsmWorkerContext>,
    ) {
        block_in_place(|| {
            thread::spawn(move || {
                let response = AsmWorkerService::process_input(&mut state, msg);
                (response, state)
            })
            .join()
            .unwrap()
        })
    }

    /// A block that syncs cleanly: `process_input` returns `Continue`, hands the
    /// caller `Ok`, and the anchor advances.
    #[tokio::test(flavor = "multi_thread")]
    async fn process_input_success_continues() {
        let fx = fixtures::setup_state(101).await;
        let target = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 102
        let (tx, rx) = oneshot::channel();
        let msg = AsmWorkerMessage::SubmitBlock(
            target.blkid().to_block_hash(),
            CommandCompletionSender::new(tx),
        );

        let (response, state) = process_input_off_runtime(fx.state, msg);

        assert!(matches!(response.unwrap(), Response::Continue));
        assert_eq!(
            rx.await.unwrap().unwrap(),
            vec![target],
            "caller received the processed block",
        );
        assert_eq!(state.blkid, target, "anchor advanced");
    }

    /// A failing sync fails the worker's task: `process_input` returns an `Err`,
    /// which the service framework turns into a critical-task failure, and the
    /// error also reaches the caller. Returning `Ok(Response::ShouldExit)` instead
    /// would end the worker cleanly, which the host cannot tell apart from the
    /// worker finishing its work. The bogus id can't be resolved to a height, so
    /// the sync fails at the up-front lookup.
    #[tokio::test(flavor = "multi_thread")]
    async fn process_input_failure_is_fatal() {
        let fx = fixtures::setup_state(101).await;
        let bogus = L1BlockId::from(Buf32::from([0xcd; 32])).to_block_hash();
        let (tx, rx) = oneshot::channel();
        let msg = AsmWorkerMessage::SubmitBlock(bogus, CommandCompletionSender::new(tx));

        let (response, _state) = process_input_off_runtime(fx.state, msg);

        assert!(
            response.is_err(),
            "a fatal sync error must propagate out of the worker task, not exit it cleanly",
        );
        assert!(rx.await.unwrap().is_err(), "caller received the error");
    }
}
