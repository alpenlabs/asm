//! Service framework integration for ASM.

use std::marker;

use serde::{Deserialize, Serialize};
use strata_asm_common::AsmSpec;
use strata_btc_types::BlockHashExt;
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_service::{Response, Service, SyncService};
use tracing::*;

use crate::{
    AsmState, AsmWorkerServiceState, SyncError, SyncPlan, WorkerError, message::AsmWorkerMessage,
    plan_sync, traits::WorkerContext,
};

/// ASM service implementation using the service framework.
#[derive(Debug)]
pub struct AsmWorkerService<W, S> {
    _phantom: marker::PhantomData<(W, S)>,
}

impl<W, S> Service for AsmWorkerService<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    type State = AsmWorkerServiceState<W, S>;
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

impl<W, S> SyncService for AsmWorkerService<W, S>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    fn process_input(
        state: &mut AsmWorkerServiceState<W, S>,
        input: AsmWorkerMessage,
    ) -> anyhow::Result<Response> {
        match input {
            AsmWorkerMessage::SubmitBlock(target, completion) => {
                // The wire carries a bitcoin block hash; translate it to the
                // worker's L1 block id at this boundary so nothing downstream
                // deals in bitcoin types.
                let result = sync_to_block(state, &target.to_l1_block_id());
                if let Err(err) = &result {
                    // A sync error is fatal: the worker exits below. Log it here
                    // so the shutdown reason lands in the worker's own log, not
                    // only in the caller's completion result (which may be
                    // awaited on another task).
                    error!(%target, %err, "ASM sync failed; shutting down worker");
                }
                let should_exit = result.is_err();
                completion.send_blocking(result);
                if should_exit {
                    return Ok(Response::ShouldExit);
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
/// lower height). Runs in two phases:
///
/// 1. **Plan** (backward): from `target`, follow parent links via each block's `prev_blockhash`
///    back to the base — the most recent ancestor with a stored `AsmState` — collecting the
///    unprocessed blocks in between. This walks `target`'s own ancestry, so on an L1 reorg the base
///    is the fork point and the abandoned branch is never visited. Only block headers are read
///    here, so a deep reorg does not load every intervening block into memory at once. See
///    [`plan_block_processing`].
///
/// 2. **Process** (forward): from the base forward (oldest first, so heights are contiguous and
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
fn sync_to_block<W, S>(
    state: &mut AsmWorkerServiceState<W, S>,
    target_blkid: &L1BlockId,
) -> crate::WorkerResult<Vec<L1BlockCommitment>>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
{
    // Resolve the submitted id to a height-tagged commitment. This is the only
    // height the worker takes from outside; every later height is derived from
    // the parent chain as the STF processes each block.
    let genesis_height = state.genesis_height();
    let height = state.context.get_l1_block_height(target_blkid)? as u32;
    let target = L1BlockCommitment::new(height, *target_blkid);

    // Ignore blocks before genesis.
    if height < genesis_height as u32 {
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

    state.update_anchor_state(base_state, base_block);

    // Phase 2: process the pending blocks oldest first. Collect them in applied
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
/// [`SyncPlan<AsmState>`]: the base — the most recent ancestor with a stored
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
) -> crate::WorkerResult<SyncPlan<AsmState>> {
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
        |block| {
            let header = ctx.get_l1_block_header(block.blkid())?;
            Ok(L1BlockCommitment::new(
                block.height() - 1,
                header.prev_blockhash.to_l1_block_id(),
            ))
        },
    )
    .map_err(|e| match e {
        SyncError::ReachedFloor { .. } => {
            error!(%target, genesis_height, "ASM hasn't found base anchor state at genesis");
            WorkerError::MissingGenesisState
        }
        SyncError::Provider(e) => e,
    })
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
fn apply_block<W, S>(
    state: &mut AsmWorkerServiceState<W, S>,
    block_id: &L1BlockCommitment,
) -> crate::WorkerResult<()>
where
    W: WorkerContext + Send + Sync + 'static,
    S: AsmSpec + Send + Sync + 'static,
    S::Params: Send + Sync + 'static,
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
    // crash before it leaves the block uncommitted to be safely re-run.
    let new_state = AsmState::from_output(asm_stf_out);
    state.context.store_anchor_state(block_id, &new_state)?;
    state.update_anchor_state(new_state, *block_id);

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
    pub cur_state: Option<AsmState>,
}

impl AsmWorkerStatus {
    /// Get the logs from the current ASM state.
    ///
    /// Returns an empty slice if the state is not initialized.
    pub fn logs(&self) -> &[strata_asm_common::AsmLogEntry] {
        self.cur_state
            .as_ref()
            .map(|s| s.logs().as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use bitcoind_async_client::traits::Reader;
    use strata_asm_common::{AsmManifestHash, AuxRequestCollector};
    use strata_btc_types::L1BlockIdBitcoinExt;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_service::CommandCompletionSender;
    use tokio::{sync::oneshot, task::block_in_place};

    use super::*;
    use crate::{
        AnchorStateStore, AuxDataResolver, ManifestMmrStore, WorkerError,
        subscription::AsmSubscribers,
        test_utils::{
            TestAsmWorkerContext,
            fixtures::{self, TestAsmSpec},
        },
    };

    /// Leaf count of the accumulator carried by the current in-memory anchor —
    /// the snapshot size [`AsmWorkerServiceState::transition`] resolves aux data
    /// against.
    fn anchor_leaf_count(state: &AsmWorkerServiceState<TestAsmWorkerContext, TestAsmSpec>) -> u64 {
        state
            .anchor
            .state()
            .chain_view
            .history_accumulator
            .num_entries()
    }

    /// Pending block heights in the order they're processed (oldest first).
    ///
    /// `plan.pending` is stored newest-first; reversing here keeps the test
    /// expectations ascending, which is easier to read.
    fn pending_heights(plan: &SyncPlan<AsmState>) -> Vec<u32> {
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
        let fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 2).await; // 102, 103
        let target = mined[0]; // 102

        fx.state
            .context
            .store_anchor_state(&target, &fx.state.anchor)
            .unwrap();

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
        let fx = fixtures::setup_state(101).await;

        // Branch A, fully "processed": 102 (the eventual fork point) and 103a.
        let fork_point = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 102
        let old_tip = fixtures::mine(&fx.node, &fx.client, 1).await[0]; // 103a
        for blk in [fork_point, old_tip] {
            fx.state
                .context
                .store_anchor_state(&blk, &fx.state.anchor)
                .unwrap();
        }

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
        // Sentinels 0..=101 (102 leaves) plus one manifest per processed height.
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
                .get_latest_asm_state()
                .unwrap()
                .map(|(b, _)| b),
            Some(tip),
            "latest tracks the tip after the initial sync",
        );

        sync_to_block(&mut fx.state, earlier.blkid()).expect("resync to the earlier block");

        // The durable pointer is unmoved by the stale notification...
        assert_eq!(
            fx.state
                .context
                .get_latest_asm_state()
                .unwrap()
                .map(|(b, _)| b),
            Some(tip),
            "latest stays at the real tip",
        );

        // ...so a restart over the same store resumes at the tip.
        let context = fx.state.context.clone();
        let params = fixtures::genesis_params(&fx.client, 101).await;
        let reloaded =
            AsmWorkerServiceState::new(context, TestAsmSpec, params, AsmSubscribers::default())
                .unwrap();
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
        let leaves_a = fx.state.context.mmr_leaves();

        // Reorg below 103 and process a longer branch B: 103b, 104b, 105b.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, 103, 3).await;
        let new_tip = *branch_b.last().unwrap();
        sync_to_block(&mut fx.state, new_tip.blkid()).expect("sync branch B");
        let leaves_b = fx.state.context.mmr_leaves();

        assert_eq!(fx.state.blkid, new_tip, "anchor on the new branch");
        // Heights 103, 104 overwritten in place; 105 appended — not 108 leaves.
        assert_eq!(leaves_b.len(), 106, "overwrite, not append");
        assert_ne!(
            leaves_b[103], leaves_a[103],
            "leaf 103 now reflects branch B"
        );
        assert_eq!(leaves_b[102], leaves_a[102], "the fork point is untouched");
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

        // The resolver runs against the current anchor's accumulator: sentinels
        // 0..=5 plus one manifest per processed height 6..=9.
        let leaf_count_a = anchor_leaf_count(&fx.state);
        assert_eq!(leaf_count_a, 10);

        // Everything up to height 9 resolves against chain A.
        let resolver_a = AuxDataResolver::new(&fx.state.context, leaf_count_a);
        let mut req_a = AuxRequestCollector::new(0, leaf_count_a);
        req_a.request_manifest_hashes(6, 9);
        let data = resolver_a
            .resolve(&req_a.into_requests())
            .expect("resolve 6..=9 on chain A");
        assert_eq!(
            data.manifest_hashes().len(),
            4,
            "one entry per height 6..=9"
        );

        // Snapshot chain A's stored leaves to compare after the reorg.
        let leaves_a = fx.state.context.mmr_leaves();

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
        for height in [8u64, 9] {
            let hash = fx
                .state
                .context
                .get_manifest_hash(height)
                .expect("orphaned hash still fetchable");
            assert_eq!(
                hash,
                AsmManifestHash::from(leaves_a[height as usize]),
                "leaf {height} still holds chain A's hash",
            );
        }
        // Heights 6,7 were overwritten in place by branch B.
        let leaves_b = fx.state.context.mmr_leaves();
        assert_ne!(leaves_b[6], leaves_a[6], "leaf 6 now reflects branch B");

        // The post-reorg accumulator is shorter: sentinels 0..=5 plus 6',7'.
        let leaf_count_b = anchor_leaf_count(&fx.state);
        assert_eq!(leaf_count_b, 8, "snapshot shrank to branch B's length");
        let resolver_b = AuxDataResolver::new(&fx.state.context, leaf_count_b);

        // Branch B's own heights still resolve.
        let mut req_b = AuxRequestCollector::new(0, leaf_count_b);
        req_b.request_manifest_hashes(6, 7);
        resolver_b
            .resolve(&req_b.into_requests())
            .expect("6'..=7' resolve on branch B");

        // (2) But the orphaned 8,9 can't be proven against the shorter snapshot:
        // their index sits at/over the snapshot leaf count, so proof generation
        // fails at the first such index (8). The collector would normally drop
        // such a request as out-of-bounds, so bypass that clamp to exercise the
        // resolver-level guarantee directly.
        let mut req_orphans = AuxRequestCollector::new(0, u64::MAX);
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
        // Sentinels 0..=101 (102 leaves) plus the one manifest just recorded.
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
        let first_leaf = fx.state.context.mmr_leaves()[102];
        let first_state = fx.state.context.get_anchor_state(&block).unwrap();
        let first_count = fx.state.context.mmr_leaf_count();

        // Rewind the in-memory anchor to the parent (as a crash before the
        // anchor-state commit would leave it) and re-run the block.
        fx.state.update_anchor_state(genesis_state, genesis_blk);
        apply_block(&mut fx.state, &block).expect("re-apply");

        assert_eq!(
            fx.state.context.mmr_leaves()[102],
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
        mut state: AsmWorkerServiceState<TestAsmWorkerContext, TestAsmSpec>,
        msg: AsmWorkerMessage,
    ) -> (
        anyhow::Result<Response>,
        AsmWorkerServiceState<TestAsmWorkerContext, TestAsmSpec>,
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

    /// A failing sync shuts the worker down: `process_input` returns `ShouldExit`
    /// and the error reaches the caller. The bogus id can't be resolved to a
    /// height, so the sync fails at the up-front lookup.
    #[tokio::test(flavor = "multi_thread")]
    async fn process_input_failure_exits() {
        let fx = fixtures::setup_state(101).await;
        let bogus = L1BlockId::from(Buf32::from([0xcd; 32])).to_block_hash();
        let (tx, rx) = oneshot::channel();
        let msg = AsmWorkerMessage::SubmitBlock(bogus, CommandCompletionSender::new(tx));

        let (response, _state) = process_input_off_runtime(fx.state, msg);

        assert!(matches!(response.unwrap(), Response::ShouldExit));
        assert!(rx.await.unwrap().is_err(), "caller received the error");
    }
}
