//! Service framework integration for ASM.

use std::marker;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use strata_asm_common::{AnchorState, AsmSpecId};
use strata_asm_stf::AsmTargetSet;
use strata_btc_types::BlockHashExt;
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_predicate::PredicateKey;
use strata_service::{Response, Service, SyncService};
use tracing::*;

use crate::{
    AsmWorkerServiceState, SyncPlan, WorkerError, derive_next_predicate, message::AsmWorkerMessage,
    traits::WorkerContext,
};

/// ASM service implementation using the service framework.
#[derive(Debug)]
pub struct AsmWorkerService<W, T> {
    _phantom: marker::PhantomData<(W, T)>,
}

impl<W, T> Service for AsmWorkerService<W, T>
where
    W: WorkerContext + Send + Sync + 'static,
    T: AsmTargetSet,
{
    type State = AsmWorkerServiceState<W, T>;
    type Msg = AsmWorkerMessage;
    type Status = AsmWorkerStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        let predicate = state.predicate().clone();
        AsmWorkerStatus {
            is_initialized: true,
            cur_block: Some(state.blkid),
            cur_state: Some(state.anchor.clone()),
            // Resolved rather than stored: reporting the predicate alongside the
            // rules it actually selects on *this* build is what makes the two
            // answerable together. `None` is the halt condition — the chain has
            // enacted rules this release does not implement.
            cur_spec: state.targets.spec_id_for(&predicate),
            next_predicate: predicate,
        }
    }
}

impl<W, T> SyncService for AsmWorkerService<W, T>
where
    W: WorkerContext + Send + Sync + 'static,
    T: AsmTargetSet,
{
    fn process_input(
        state: &mut AsmWorkerServiceState<W, T>,
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
/// lower height). Runs in two phases:
///
/// 1. **Plan** (backward): walk both `target` and the in-memory tip back to their common ancestor,
///    collecting the target branch in between. The base is the fork point even when target-branch
///    anchors from an earlier visit are still stored; those blocks must be replayed to restore
///    height-indexed derived storage such as the manifest MMR. Only headers are read during the
///    walk. See [`plan_block_processing`].
///
/// 2. **Process** (forward): from the base forward (oldest first, so heights are contiguous and
///    strictly increasing), fetch each full block, run the STF, then persist its manifest into the
///    height-indexed MMR, its aux data, and its anchor state, advancing the in-memory anchor as it
///    goes. Processing a height already handled on the old branch overwrites that branch's leaf in
///    place, which is why the manifest MMR supports leaf replacement. See [`apply_block`].
///
/// A duplicate of the current tip produces an empty plan and no state change.
/// An ancestor target is an authoritative rollback to a shorter tip: its stored
/// state and handover are adopted without re-running a block. A target on
/// another retained branch is replayed from the common ancestor even if every
/// one of its states is already stored; merely loading its tip would leave
/// height-indexed derived storage on the abandoned branch.
///
/// Returns the commitments processed, oldest first — possibly several blocks for
/// one submit, or empty when the target is already processed or before genesis.
///
/// A `target` before genesis is ignored (returns `Ok`). If the backward walk
/// descends below genesis without finding a stored anchor state, returns
/// `WorkerError::MissingGenesisState`. Any fetch, transition, or storage error
/// is propagated; the caller treats it as fatal and shuts the worker down.
fn sync_to_block<W, T>(
    state: &mut AsmWorkerServiceState<W, T>,
    target_blkid: &L1BlockId,
) -> crate::WorkerResult<Vec<L1BlockCommitment>>
where
    W: WorkerContext + Send + Sync + 'static,
    T: AsmTargetSet,
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
    } = plan_block_processing(&state.context, &target, &state.blkid, genesis_height)?;

    info!(%base_block,
        pending_blocks = pending.len(),
        "ASM found processing base"
    );
    drop(plan_span_guard);

    // A duplicate of the exact current tip is the only no-op. `hashblock`
    // follows active-tip updates, so an ancestor target is an authoritative
    // shorter reorg and must move the durable tip even though it has no suffix
    // to replay.
    if pending.is_empty() && base_block == state.blkid {
        warn!(
            %target,
            "block already processed; ignoring duplicate current-tip notification"
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

    if base_block != state.blkid {
        // A retained ancestor is untrusted storage input at the point it becomes
        // active again. Bind its decoded state to the selected commitment, fully
        // validate it under its persisted handover, and authenticate any
        // predecessor boundary before changing either durable or in-memory
        // state. Handovers on other branches remain isolated by full commitment.
        let base_predicate = state.validate_rebase_anchor(base_block, &base_state)?;

        // Persist the reorg point before applying its replacement suffix. If a
        // crash happens between blocks, restart resumes from a canonical prefix
        // rather than the abandoned (possibly higher) tip.
        state.context.store_anchor_state(&base_state)?;
        state.update_anchor_state(base_state, base_block);
        state.adopt_predicate(base_predicate);
    }

    if pending.is_empty() {
        // No STF block committed during an ancestor rollback, but downstream
        // derived workers still need an authoritative tip event so they can
        // durably re-anchor and trim their own suffixes.
        state.subscribers.emit(base_block);
        return Ok(vec![]);
    }

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

/// Walks `target` and `current_tip` back to their common ancestor and returns
/// the target-branch blocks above it, newest first.
///
/// Stored states on a previously visited target branch do not stop the walk.
/// The manifest MMR is a single height-indexed canonical projection, so every
/// replacement block from the fork point forward must run again to overwrite
/// that projection. The common ancestor belongs to the current committed branch
/// and must have a stored anchor state; its absence is storage corruption.
fn plan_block_processing<W: WorkerContext>(
    ctx: &W,
    target: &L1BlockCommitment,
    current_tip: &L1BlockCommitment,
    genesis_height: u64,
) -> crate::WorkerResult<SyncPlan<AnchorState>> {
    let (base_block, pending) =
        plan_target_branch(*target, *current_tip, genesis_height, |block| {
            parent_of(ctx, block)
        })?;

    let base_state = match ctx.get_anchor_state(&base_block) {
        Ok(anchor) => anchor,
        Err(WorkerError::MissingAsmState(_))
            if u64::from(base_block.height()) == genesis_height =>
        {
            error!(%target, genesis_height, "ASM hasn't found base anchor state at genesis");
            return Err(WorkerError::MissingGenesisState);
        }
        Err(error) => return Err(error),
    };

    Ok(SyncPlan {
        base_state,
        base_block,
        pending,
    })
}

/// Computes the target suffix above its common ancestor with `current_tip`.
///
/// This is storage-independent by design: whether a target block was processed
/// on an earlier visit does not change the suffix that must be replayed to move
/// height-indexed derived storage onto that branch.
fn plan_target_branch(
    target: L1BlockCommitment,
    current_tip: L1BlockCommitment,
    genesis_height: u64,
    mut parent_of: impl FnMut(L1BlockCommitment) -> crate::WorkerResult<L1BlockCommitment>,
) -> crate::WorkerResult<(L1BlockCommitment, Vec<L1BlockCommitment>)> {
    let mut target_cursor = target;
    let mut current_cursor = current_tip;
    let mut pending = Vec::new();

    // Align heights. Blocks removed from the target side are exactly the suffix
    // the forward pass must apply; blocks removed from the current side belong
    // to the branch being abandoned.
    while target_cursor.height() > current_cursor.height() {
        pending.push(target_cursor);
        target_cursor = checked_parent(target_cursor, genesis_height, target, &mut parent_of)?;
    }
    while current_cursor.height() > target_cursor.height() {
        current_cursor = checked_parent(current_cursor, genesis_height, target, &mut parent_of)?;
    }

    // Walk siblings in lockstep until the exact full commitment matches.
    while target_cursor != current_cursor {
        pending.push(target_cursor);
        target_cursor = checked_parent(target_cursor, genesis_height, target, &mut parent_of)?;
        current_cursor = checked_parent(current_cursor, genesis_height, target, &mut parent_of)?;
    }

    Ok((target_cursor, pending))
}

/// Refuses to walk below the configured genesis floor.
fn checked_parent(
    block: L1BlockCommitment,
    genesis_height: u64,
    target: L1BlockCommitment,
    parent_of: &mut impl FnMut(L1BlockCommitment) -> crate::WorkerResult<L1BlockCommitment>,
) -> crate::WorkerResult<L1BlockCommitment> {
    if u64::from(block.height()) <= genesis_height {
        error!(%target, genesis_height, "ASM target and current tip do not share the configured genesis anchor");
        return Err(WorkerError::MissingGenesisState);
    }
    parent_of(block)
}

/// Resolves a commitment's parent from its Bitcoin header.
fn parent_of<W: WorkerContext>(
    ctx: &W,
    block: L1BlockCommitment,
) -> crate::WorkerResult<L1BlockCommitment> {
    let header = ctx.get_l1_block_header(block.blkid())?;
    Ok(L1BlockCommitment::new(
        block.height() - 1,
        header.prev_blockhash.to_l1_block_id(),
    ))
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
fn apply_block<W, T>(
    state: &mut AsmWorkerServiceState<W, T>,
    block_id: &L1BlockCommitment,
) -> crate::WorkerResult<()>
where
    W: WorkerContext + Send + Sync + 'static,
    T: AsmTargetSet,
{
    // Fetch the full block now, one height at a time, so only a single block is
    // resident at any point during the forward pass.
    let block = state.context.get_l1_block(block_id.blkid())?;
    let (asm_stf_out, aux_data) = state.transition(&block)?;

    // Derive the predicate this block hands over, and persist it *before* the
    // anchor commits. That ordering is the point: a committed anchor must never
    // lack the handover it enacted, or a restart would not know which rules the
    // next block runs under. Re-running an uncommitted block rewrites the same
    // value, because the derivation is a pure function of the block.
    let next_predicate = derive_next_predicate(state.predicate(), &asm_stf_out.manifest);
    state
        .context
        .store_next_predicate(block_id, &next_predicate)?;

    // Persist the manifest and record its hash in the height-indexed MMR.
    state
        .context
        .record_manifest(asm_stf_out.manifest.clone())?;
    // Store auxiliary data for prover consumption.
    state.context.store_aux_data(block_id, &aux_data)?;

    // Anchor state last: it is the block's commit point (see fn docs), so a
    // crash before it leaves the block uncommitted to be safely re-run. The
    // STF's logs are already persisted in the manifest recorded above.
    let new_state = asm_stf_out.state;
    state.context.store_anchor_state(&new_state)?;
    state.update_anchor_state(new_state, *block_id);
    state.adopt_predicate(next_predicate);

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

    /// The specification the next block will execute under, or `None` when this
    /// build cannot execute [`next_predicate`](Self::next_predicate).
    ///
    /// `None` means the node is halted at an upgrade it does not implement — the
    /// one operational state that cannot be read off the anchor state, because a
    /// halted node's anchor looks exactly like a healthy one that is simply idle.
    pub cur_spec: Option<AsmSpecId>,

    /// The predicate authorizing the next block, as handed over by the current
    /// anchor. This is the value that selects the rules, so it is what an
    /// operator compares against a release's bindings.
    pub next_predicate: PredicateKey,
}

#[cfg(test)]
mod ancestry_tests {
    use std::collections::HashMap;

    use strata_identifiers::{Buf32, L1BlockId};

    use super::*;

    fn block(height: u32, seed: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::from([seed; 32])))
    }

    fn plan(
        target: L1BlockCommitment,
        current: L1BlockCommitment,
        genesis_height: u64,
        parents: HashMap<L1BlockCommitment, L1BlockCommitment>,
    ) -> crate::WorkerResult<(L1BlockCommitment, Vec<L1BlockCommitment>)> {
        plan_target_branch(target, current, genesis_height, |child| {
            parents
                .get(&child)
                .copied()
                .ok_or(WorkerError::MissingGenesisState)
        })
    }

    #[test]
    fn target_extension_replays_only_the_new_suffix() {
        let genesis = block(100, 0);
        let b101 = block(101, 1);
        let b102 = block(102, 2);

        let (base, pending) = plan(
            b102,
            genesis,
            100,
            HashMap::from([(b102, b101), (b101, genesis)]),
        )
        .unwrap();

        assert_eq!(base, genesis);
        assert_eq!(pending, vec![b102, b101]);
    }

    #[test]
    fn shorter_ancestor_target_selects_the_ancestor_as_reanchor_base() {
        let genesis = block(100, 0);
        let b101 = block(101, 1);
        let b102 = block(102, 2);

        let (base, pending) = plan(
            b101,
            b102,
            100,
            HashMap::from([(b102, b101), (b101, genesis)]),
        )
        .unwrap();

        assert_eq!(base, b101);
        assert!(
            pending.is_empty(),
            "an ancestor rollback has no blocks to execute, but its distinct base must be adopted",
        );
    }

    #[test]
    fn retained_sibling_branch_is_replayed_from_the_fork() {
        let genesis = block(100, 0);
        let fork = block(101, 1);
        let a102 = block(102, 0xaa);
        let a103 = block(103, 0xab);
        let b102 = block(102, 0xba);
        let b103 = block(103, 0xbb);

        let (base, pending) = plan(
            a103,
            b103,
            100,
            HashMap::from([
                (a103, a102),
                (a102, fork),
                (b103, b102),
                (b102, fork),
                (fork, genesis),
            ]),
        )
        .unwrap();

        assert_eq!(base, fork);
        assert_eq!(pending, vec![a103, a102]);
    }

    #[test]
    fn unrelated_genesis_anchors_are_rejected() {
        let genesis_a = block(100, 0xaa);
        let genesis_b = block(100, 0xbb);

        let error = plan(genesis_a, genesis_b, 100, HashMap::new()).unwrap_err();
        assert!(matches!(error, WorkerError::MissingGenesisState));
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use bitcoind_async_client::traits::Reader;
    use strata_asm_common::{AuxRequestCollector, SectionState, SectionStateExt};
    use strata_btc_types::L1BlockIdBitcoinExt;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_service::CommandCompletionSender;
    use tokio::{sync::oneshot, task::block_in_place};

    use super::*;
    use crate::{
        AnchorStateStore, AsmHandoverStore, AuxDataResolver, ManifestMmrStore, Subscribers,
        WorkerError,
        test_utils::{
            TestAsmWorkerContext,
            fixtures::{self, TestAsmTargets},
        },
    };

    /// Leaf count of the accumulator carried by the current in-memory anchor —
    /// the snapshot size [`AsmWorkerServiceState::transition`] resolves aux data
    /// against.
    fn anchor_leaf_count(
        state: &AsmWorkerServiceState<TestAsmWorkerContext, TestAsmTargets>,
    ) -> u64 {
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

        let plan = plan_block_processing(
            &fx.state.context,
            &target,
            &fx.state.blkid,
            fx.state.genesis_height(),
        )
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

        let plan = plan_block_processing(
            &fx.state.context,
            &target,
            &fx.state.blkid,
            fx.state.genesis_height(),
        )
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

        let plan = plan_block_processing(
            &fx.state.context,
            &new_tip,
            &fx.state.blkid,
            fx.state.genesis_height(),
        )
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
        let genesis = fx.client.get_block_hash(101).await.unwrap();
        let current_tip = L1BlockCommitment::new(101, genesis.to_l1_block_id());

        let result = plan_block_processing(&fx.context, &target, &current_tip, 101);

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

    /// An active-chain rollback to an already-processed ancestor adopts that
    /// ancestor without re-running it. The height-indexed MMR suffix can remain:
    /// the adopted anchor's accumulator leaf count scopes all proof reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_shorter_ancestor_reanchors_without_reprocessing() {
        let mut fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 2).await; // 102, 103
        let earlier = mined[0];
        let tip = mined[1];

        sync_to_block(&mut fx.state, tip.blkid()).expect("initial sync");
        let leaves_after_sync = fx.state.context.mmr_leaf_count();
        assert_eq!(fx.state.blkid, tip);
        let mut reanchors = fx.state.subscribers.subscribe();

        fx.node
            .client
            .invalidate_block(tip.blkid().to_block_hash())
            .expect("roll active chain back to 102");

        let processed = sync_to_block(&mut fx.state, earlier.blkid()).expect("resync");

        assert!(
            processed.is_empty(),
            "an already-processed ancestor runs no STF block",
        );
        assert_eq!(fx.state.blkid, earlier, "the shorter active tip is adopted");
        assert_eq!(
            fx.state.context.mmr_leaf_count(),
            leaves_after_sync,
            "the suffix is retained and hidden by the anchor snapshot size",
        );
        assert_eq!(reanchors.try_recv(), Ok(earlier));
    }

    /// A retained snapshot becomes untrusted input when a reorg tries to make
    /// it active again. Validation must fail before the durable tip, in-memory
    /// anchor/predicate, MMR, or subscriber stream moves to that snapshot.
    #[tokio::test(flavor = "multi_thread")]
    async fn reorg_rejects_an_invalid_retained_base_before_adoption() {
        let mut fx = fixtures::setup_state(101).await;
        let mined = fixtures::mine(&fx.node, &fx.client, 2).await; // 102, 103
        let earlier = mined[0];
        let tip = mined[1];

        sync_to_block(&mut fx.state, tip.blkid()).expect("initial sync");
        let mut corrupt = fx
            .state
            .context
            .get_anchor_state(&earlier)
            .expect("read retained ancestor");
        corrupt.sections[0].version = u8::MAX;
        fx.state.context.overwrite_anchor_snapshot(&corrupt);

        let durable_before = fx.state.context.get_latest_anchor_state().unwrap();
        let in_memory_anchor_before = fx.state.anchor.clone();
        let predicate_before = fx.state.predicate().clone();
        let leaves_before = fx.state.context.mmr_leaf_count();
        let mut reanchors = fx.state.subscribers.subscribe();

        fx.node
            .client
            .invalidate_block(tip.blkid().to_block_hash())
            .expect("roll active chain back to the corrupt retained ancestor");

        let error = sync_to_block(&mut fx.state, earlier.blkid())
            .expect_err("an invalid retained base must not be adopted");

        assert!(matches!(
            error,
            WorkerError::InvalidStoredProducerState { block, .. } if block == earlier
        ));
        assert_eq!(fx.state.blkid, tip, "in-memory tip must not move");
        assert_eq!(fx.state.anchor, in_memory_anchor_before);
        assert_eq!(fx.state.predicate(), &predicate_before);
        assert_eq!(
            fx.state.context.get_latest_anchor_state().unwrap(),
            durable_before
        );
        assert_eq!(fx.state.context.mmr_leaf_count(), leaves_before);
        assert!(
            reanchors.try_recv().is_err(),
            "failed adoption must not emit a reanchor event",
        );
    }

    /// Reorg validation applies the bootstrap identity rule as well as generic
    /// schema checks. A same-key, canonically encoded but semantically altered
    /// genesis snapshot cannot become active after startup.
    #[tokio::test(flavor = "multi_thread")]
    async fn reorg_rejects_an_altered_bootstrap_snapshot_before_adoption() {
        let mut fx = fixtures::setup_state(101).await;
        let genesis = fx.state.bootstrap.anchor_block();
        let tip = fixtures::mine(&fx.node, &fx.client, 1).await[0];
        sync_to_block(&mut fx.state, tip.blkid()).expect("initial sync");

        let mut altered = fx.state.bootstrap.genesis_state().clone();
        altered.sections[0] =
            SectionState::from_state::<fixtures::TestSubprotocolV0>(&9).expect("test state fits");
        fx.state.context.overwrite_anchor_snapshot(&altered);

        let durable_before = fx.state.context.get_latest_anchor_state().unwrap();
        let in_memory_anchor_before = fx.state.anchor.clone();
        let predicate_before = fx.state.predicate().clone();
        let leaves_before = fx.state.context.mmr_leaf_count();
        let mut reanchors = fx.state.subscribers.subscribe();

        fx.node
            .client
            .invalidate_block(tip.blkid().to_block_hash())
            .expect("roll active chain back to genesis");

        let error = sync_to_block(&mut fx.state, genesis.blkid())
            .expect_err("an altered bootstrap snapshot must not be adopted");

        assert!(matches!(
            error,
            WorkerError::StoredBootstrapMismatch {
                bootstrap,
                actual,
            } if bootstrap == genesis && actual == genesis
        ));
        assert_eq!(fx.state.blkid, tip);
        assert_eq!(fx.state.anchor, in_memory_anchor_before);
        assert_eq!(fx.state.predicate(), &predicate_before);
        assert_eq!(
            fx.state.context.get_latest_anchor_state().unwrap(),
            durable_before
        );
        assert_eq!(fx.state.context.mmr_leaf_count(), leaves_before);
        assert!(reanchors.try_recv().is_err());
    }

    /// The exact genesis-predicate rule survives startup: changing the persisted
    /// bootstrap handover while the worker is above genesis cannot authorize a
    /// later rollback, even when the substitute maps to the same spec.
    #[tokio::test(flavor = "multi_thread")]
    async fn reorg_rejects_a_same_spec_bootstrap_handover_substitution() {
        let mut fx = fixtures::setup_state(101).await;
        let genesis = fx.state.bootstrap.anchor_block();
        let tip = fixtures::mine(&fx.node, &fx.client, 1).await[0];
        sync_to_block(&mut fx.state, tip.blkid()).expect("initial sync");
        fx.state
            .context
            .store_next_predicate(&genesis, &fixtures::test_rotated_baseline_predicate())
            .expect("replace bootstrap handover offline");

        let durable_before = fx.state.context.get_latest_anchor_state().unwrap();
        let in_memory_anchor_before = fx.state.anchor.clone();
        let predicate_before = fx.state.predicate().clone();
        let leaves_before = fx.state.context.mmr_leaf_count();
        let mut reanchors = fx.state.subscribers.subscribe();

        fx.node
            .client
            .invalidate_block(tip.blkid().to_block_hash())
            .expect("roll active chain back to genesis");

        let error = sync_to_block(&mut fx.state, genesis.blkid())
            .expect_err("an altered bootstrap handover must not be adopted");

        assert!(matches!(
            error,
            WorkerError::BootstrapHandoverMismatch { block, .. } if block == genesis
        ));
        assert_eq!(fx.state.blkid, tip);
        assert_eq!(fx.state.anchor, in_memory_anchor_before);
        assert_eq!(fx.state.predicate(), &predicate_before);
        assert_eq!(
            fx.state.context.get_latest_anchor_state().unwrap(),
            durable_before
        );
        assert_eq!(fx.state.context.mmr_leaf_count(), leaves_before);
        assert!(reanchors.try_recv().is_err());
    }

    /// A shorter ancestor rollback updates the durable active pointer, so restart
    /// cannot select the retained higher orphan by key ordering.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_shorter_ancestor_is_the_restart_tip() {
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
                .map(|(block, _state)| block),
            Some(tip),
            "latest tracks the tip after the initial sync",
        );

        fx.node
            .client
            .invalidate_block(tip.blkid().to_block_hash())
            .expect("roll active chain back to 102");
        sync_to_block(&mut fx.state, earlier.blkid()).expect("resync to the earlier block");

        assert_eq!(
            fx.state
                .context
                .get_latest_anchor_state()
                .unwrap()
                .map(|(block, _state)| block),
            Some(earlier),
            "latest follows the authoritative shorter tip",
        );

        let context = fx.state.context.clone();
        let bootstrap = fixtures::genesis_bootstrap(&fx.client, 101).await;
        let reloaded = AsmWorkerServiceState::new(
            context,
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            bootstrap,
            Subscribers::default(),
        )
        .unwrap();
        assert_eq!(
            reloaded.blkid, earlier,
            "restart ignores the retained higher orphan",
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

    /// Switching back to a branch whose anchors are already retained must
    /// replay that branch from the common ancestor. Loading its stored tip alone
    /// would leave the height-indexed manifest MMR on the branch being abandoned.
    #[tokio::test(flavor = "multi_thread")]
    async fn sync_replays_an_already_stored_branch_and_persists_its_tip() {
        let mut fx = fixtures::setup_state(101).await;

        // Process branch A and remember its canonical projection.
        let branch_a = fixtures::mine(&fx.node, &fx.client, 3).await; // 102, 103a, 104a
        let tip_a = *branch_a.last().unwrap();
        sync_to_block(&mut fx.state, tip_a.blkid()).expect("sync branch A");
        let leaf_a_103 = fx
            .state
            .context
            .get_manifest_hash(103)
            .expect("leaf 103 on A");

        // Replace 103a..=104a with B and process it. A's block-keyed anchors and
        // handovers remain, while the external MMR now projects B.
        let branch_b = fixtures::reorg(&fx.node, &fx.client, 103, 2).await;
        let tip_b = *branch_b.last().unwrap();
        sync_to_block(&mut fx.state, tip_b.blkid()).expect("sync branch B");
        assert_ne!(
            fx.state
                .context
                .get_manifest_hash(103)
                .expect("leaf 103 on B"),
            leaf_a_103,
        );

        // Make A active again without creating any new A block. Its target is
        // therefore already stored — the recovery case this test qualifies.
        fx.node
            .client
            .invalidate_block(branch_b[0].blkid().to_block_hash())
            .expect("invalidate branch B");
        fx.node
            .client
            .reconsider_block(branch_a[1].blkid().to_block_hash())
            .expect("reconsider branch A");

        let replayed = sync_to_block(&mut fx.state, tip_a.blkid()).expect("restore branch A");

        assert_eq!(replayed, branch_a[1..], "replayed from the fork point");
        assert_eq!(fx.state.blkid, tip_a);
        assert_eq!(
            fx.state
                .context
                .get_manifest_hash(103)
                .expect("restored leaf 103 on A"),
            leaf_a_103,
            "height-indexed derived storage follows the restored branch",
        );
        assert_eq!(
            fx.state
                .context
                .get_latest_anchor_state()
                .unwrap()
                .map(|(block, _state)| block),
            Some(tip_a),
            "the restored branch is the durable active tip",
        );

        let reloaded = AsmWorkerServiceState::new(
            fx.state.context.clone(),
            fixtures::TestAsmTargets,
            fixtures::test_predicate(),
            fixtures::genesis_bootstrap(&fx.client, 101).await,
            Subscribers::default(),
        )
        .expect("restart from restored branch");
        assert_eq!(reloaded.blkid, tip_a);
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

        // The post-reorg accumulator is shorter: sentinels 0..=5 plus 6',7'.
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
        mut state: AsmWorkerServiceState<TestAsmWorkerContext, TestAsmTargets>,
        msg: AsmWorkerMessage,
    ) -> (
        anyhow::Result<Response>,
        AsmWorkerServiceState<TestAsmWorkerContext, TestAsmTargets>,
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
