//! Service framework integration for the prover worker.
//!
//! Mirrors the ASM worker (`strata-asm-worker`): a logic-only [`ProverService`]
//! ZST implements the framework traits, while all mutable data lives in
//! [`ProverServiceState`]. The service is driven by the framework's input loop,
//! fed by a [`TickingInput`](strata_service::TickingInput) that merges the ASM
//! worker's commit subscription with a periodic wakeup tick:
//!
//! - [`TickMsg::Msg`] — a newly committed block; expand it into its ASM step and Moho recursive
//!   proofs and enqueue them.
//! - [`TickMsg::Tick`] — reconcile in-flight remote proofs, then schedule pending ones.

use std::marker;

use async_trait::async_trait;
use moho_recursive_proof::MohoRecursiveProgram;
use serde::{Deserialize, Serialize};
use strata_asm_proof_impl::program::AsmStfProofProgram;
use strata_asm_prover_types::{L1Range, ProofId, RemoteProofId};
use strata_identifiers::L1BlockCommitment;
use strata_service::{AsyncService, Response, Service, TickMsg};
use tracing::{debug, error, info, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost, ZkVmRemoteProgram};

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
    input::InputBuilder,
    message::ProverMessage,
    proof_store,
    queue::PendingProofQueue,
    state::ProverServiceState,
};

/// Prover service implementation using the service framework.
///
/// A zero-sized logic holder generic over the prover context `C` and the remote
/// host `H`; all state lives in [`ProverServiceState`].
#[derive(Debug)]
pub struct ProverService<C, H> {
    _phantom: marker::PhantomData<(C, H)>,
}

impl<C, H> Service for ProverService<C, H>
where
    C: ProverContext + Send + Sync + 'static,
    H: ZkVmRemoteHost + Send + Sync + 'static,
{
    type State = ProverServiceState<C, H>;
    type Msg = ProverMessage;
    type Status = ProverStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        ProverStatus {
            pending: state.queue.len(),
            last_committed: state.last_committed,
        }
    }
}

impl<C, H> AsyncService for ProverService<C, H>
where
    C: ProverContext + Send + Sync + 'static,
    H: ZkVmRemoteHost + Send + Sync + 'static,
{
    async fn process_input(state: &mut Self::State, input: Self::Msg) -> anyhow::Result<Response> {
        match input {
            // A newly committed block: record the proofs it requires. Scheduling
            // happens on the next tick.
            TickMsg::Msg(block) => state.enqueue_block_proofs(block),

            // Periodic wakeup: drive reconcile + schedule. Transient failures are
            // logged and swallowed so the service keeps running, matching the
            // pre-framework orchestrator loop.
            TickMsg::Tick => {
                if let Err(e) = tick(state).await {
                    error!(?e, "prover tick failed");
                }
            }
        }
        Ok(Response::Continue)
    }
}

/// Executes one orchestration cycle: recover pending proofs (once), reconcile
/// in-flight proofs, then schedule pending ones.
async fn tick<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    // Rebuild the pending queue from durable state on the first tick after
    // startup. The commit subscription only re-delivers blocks the worker
    // reprocesses, and an already-processed block is a no-op on restart — so
    // proofs pending but never submitted (e.g. a Moho proof deferred on a
    // missing prerequisite) would otherwise be lost, stalling the recursive
    // chain behind the gap forever.
    //
    // Recovery is the only path that re-enqueues those blocks, so a transient
    // failure (Bitcoin RPC or sled) must not leave the queue permanently short.
    // Retry once per tick until it succeeds rather than proceeding with a
    // half-rebuilt queue; `proofs_to_backfill` is all-or-nothing (it errors
    // before enqueuing anything), so each retry is clean and the successful run
    // enqueues exactly once.
    if !state.recovered {
        match recover_pending_proofs(state).await {
            Ok(()) => state.recovered = true,
            Err(e) => error!(?e, "failed to recover pending proofs; retrying next tick"),
        }
    }

    if !state.queue.is_empty() {
        debug!(pending = state.queue.len(), "prover tick");
    }

    reconcile_active_proofs(state).await?;
    schedule_proofs(state).await?;
    Ok(())
}

/// Re-enqueues proofs that were pending at restart but are not yet completed or
/// in flight.
///
/// Enumerates every worker-processed canonical block above the highest canonical
/// block that already has a Moho proof (see [`InputBuilder`]'s
/// `proofs_to_backfill`) and enqueues its ASM and Moho proof requests.
/// Already-completed or already-submitted proofs are filtered out downstream by
/// the scheduler's `try_submit`, so this only resurrects the genuinely-missing
/// work.
async fn recover_pending_proofs<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let backfill = state.input_builder.proofs_to_backfill(&state.ctx).await?;

    if backfill.is_empty() {
        return Ok(());
    }

    info!(
        blocks = backfill.len(),
        "re-enqueuing pending proofs after restart"
    );
    for commitment in backfill {
        state
            .queue
            .enqueue(ProofId::Asm(L1Range::single(commitment)));
        state.queue.enqueue(ProofId::Moho(commitment));
    }
    Ok(())
}

// ---- Step 1: Reconcile ----------------------------------------------------

/// Polls all in-progress remote proofs and stores any that have completed.
async fn reconcile_active_proofs<C, H>(state: &ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let in_progress = state
        .ctx
        .get_all_in_progress()
        .await
        .map_err(|e| ProverError::storage("failed to query in-progress proofs", e))?;

    for (remote_id, old_status) in in_progress {
        if let Err(e) = reconcile_one(state, &remote_id, &old_status).await {
            warn!(?remote_id, ?e, "failed to reconcile remote proof");
        }
    }
    Ok(())
}

/// Reconciles a single remote proof.
async fn reconcile_one<C, H>(
    state: &ProverServiceState<C, H>,
    remote_id: &RemoteProofId,
    old_status: &RemoteProofStatus,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let typed_id = to_typed_proof_id::<H>(remote_id)?;

    // NOTE: We use `state.asm` here but this could be any host instance.
    // `get_status` only requires a network client and proof ID — not the ELF or
    // proving key. Both hosts share the same concrete type `H`, so either works.
    let new_status = state
        .asm
        .get_status(&typed_id)
        .await
        .map_err(ProverError::RemoteStatus)?;

    if &new_status == old_status {
        return Ok(());
    }

    debug!(%remote_id, ?old_status, ?new_status, "remote proof status changed");

    match &new_status {
        RemoteProofStatus::Completed => {
            handle_completed(state, remote_id, &typed_id).await?;
        }
        RemoteProofStatus::Failed(reason) => {
            error!(?remote_id, %reason, "remote proof generation failed");
            state
                .ctx
                .remove(remote_id)
                .await
                .map_err(|e| ProverError::storage("failed to remove failed proof status", e))?;
        }
        _ => {
            state
                .ctx
                .update_status(remote_id, new_status)
                .await
                .map_err(|e| ProverError::storage("failed to update proof status", e))?;
        }
    }
    Ok(())
}

/// Retrieves a completed proof and stores it in the proof store.
async fn handle_completed<C, H>(
    state: &ProverServiceState<C, H>,
    remote_id: &RemoteProofId,
    typed_id: &H::ProofId,
) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    // NOTE: As above, `get_proof` only needs a network client and the proof ID,
    // so `state.asm` works for proofs produced by either host.
    let receipt = state
        .asm
        .get_proof(typed_id)
        .await
        .map_err(ProverError::RemoteRetrieve)?;

    let proof_id = state
        .ctx
        .get_proof_id(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to look up proof ID from remote ID", e))?
        .ok_or(ProverError::NotFound(
            "no mapping found for completed remote proof",
        ))?;

    proof_store::store_completed_proof(&state.ctx, proof_id, receipt).await?;

    state
        .ctx
        .remove(remote_id)
        .await
        .map_err(|e| ProverError::storage("failed to remove completed proof status", e))?;

    Ok(())
}

// ---- Step 2: Schedule -----------------------------------------------------

/// Dequeues proofs from the pending queue and submits them to the remote prover.
///
/// Computes the available submission capacity, then delegates the loop control
/// flow to [`schedule_with`] through a short-lived [`StateSubmitter`] so the
/// scheduling loop itself can be unit-tested with a fake submitter.
async fn schedule_proofs<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let in_flight = state
        .ctx
        .get_all_in_progress()
        .await
        .map_err(|e| ProverError::storage("failed to query in-progress proofs", e))?
        .len();

    let capacity = state.config.max_concurrent_proofs.saturating_sub(in_flight);
    if capacity == 0 {
        return Ok(());
    }

    // Disjoint field borrows: the submitter reads ctx/hosts/input_builder while
    // `schedule_with` mutates the queue.
    let mut submitter = StateSubmitter {
        ctx: &state.ctx,
        asm: &state.asm,
        moho: &state.moho,
        input_builder: &state.input_builder,
    };
    schedule_with(&mut state.queue, &mut submitter, capacity).await;
    Ok(())
}

/// Outcome of a single [`ProofSubmitter::try_submit`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SubmitOutcome {
    /// Proof was submitted to the remote prover and counts against capacity.
    Submitted,
    /// Proof was already submitted or already exists locally; nothing to do.
    Skipped,
    /// Prerequisites not yet available; caller should re-enqueue for later.
    Deferred,
}

/// Submits a single proof to the remote prover.
///
/// Abstracts the "submit one proof" step so the scheduling loop in
/// [`schedule_with`] can be unit-tested against a fake submitter.
#[async_trait]
trait ProofSubmitter {
    async fn try_submit(&mut self, proof_id: ProofId) -> ProverResult<SubmitOutcome>;
}

/// Runs the scheduling loop: pulls items from `queue` and submits via
/// `submitter` until either `capacity` real submissions have been issued or the
/// queue drains.
///
/// Drains past proofs whose prerequisites are not yet satisfied (e.g. a Moho
/// proof waiting on its ASM step proof) so that independent higher-priority work
/// behind them — typically the next ASM step proof — still gets submitted within
/// the same tick. Deferred proofs (and submission errors) are parked in a local
/// buffer and re-enqueued at the end, so the same blocked item is not popped
/// twice within one loop. All submission errors are absorbed and logged.
async fn schedule_with<S: ProofSubmitter>(
    queue: &mut PendingProofQueue,
    submitter: &mut S,
    mut capacity: usize,
) {
    let mut deferred: Vec<ProofId> = Vec::new();

    while capacity > 0 {
        let Some(proof_id) = queue.dequeue_one() else {
            break;
        };
        match submitter.try_submit(proof_id).await {
            Ok(SubmitOutcome::Submitted) => capacity -= 1,
            Ok(SubmitOutcome::Skipped) => {}
            Ok(SubmitOutcome::Deferred) => deferred.push(proof_id),
            Err(e) => {
                warn!(?proof_id, %e, "failed to submit proof, re-enqueuing");
                deferred.push(proof_id);
            }
        }
    }

    for id in deferred {
        queue.enqueue(id);
    }
}

/// [`ProofSubmitter`] backed by the service state's context, hosts, and input
/// builder. Constructed inline by [`schedule_proofs`] for the duration of one
/// scheduling cycle.
struct StateSubmitter<'a, C, H> {
    ctx: &'a C,
    asm: &'a H,
    moho: &'a H,
    input_builder: &'a InputBuilder,
}

#[async_trait]
impl<C, H> ProofSubmitter for StateSubmitter<'_, C, H>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    async fn try_submit(&mut self, proof_id: ProofId) -> ProverResult<SubmitOutcome> {
        // Skip if already submitted.
        if self
            .ctx
            .get_remote_proof_id(proof_id)
            .await
            .map_err(|e| ProverError::storage("failed to check remote proof mapping", e))?
            .is_some()
        {
            debug!(?proof_id, "proof already submitted, skipping");
            return Ok(SubmitOutcome::Skipped);
        }

        // Skip if proof already exists locally.
        if proof_store::proof_exists(self.ctx, &proof_id).await? {
            debug!(?proof_id, "proof already exists, skipping");
            return Ok(SubmitOutcome::Skipped);
        }

        // Build input and submit to remote prover, dispatching by proof type.
        // `ZkVmRemoteProgram::start_proving` returns a `Send` future, so it drives
        // directly on the multi-threaded async framework.
        let typed_id = match &proof_id {
            ProofId::Asm(range) => {
                let runtime_input = self
                    .input_builder
                    .build_asm_runtime_input(self.ctx, range)
                    .await?;
                AsmStfProofProgram::start_proving(&runtime_input, self.asm)
                    .await
                    .map_err(ProverError::RemoteSubmit)?
            }
            ProofId::Moho(block) => {
                let prerequisite = match self
                    .input_builder
                    .check_moho_prerequisite(self.ctx, *block)
                    .await
                {
                    Ok(prereq) => prereq,
                    Err(e) => {
                        debug!(?proof_id, %e, "moho prerequisite not ready, deferring");
                        return Ok(SubmitOutcome::Deferred);
                    }
                };
                let input = self
                    .input_builder
                    .build_moho_runtime_input(self.ctx, prerequisite, *block)
                    .await?;
                MohoRecursiveProgram::start_proving(&input, self.moho)
                    .await
                    .map_err(ProverError::RemoteSubmit)?
            }
        };

        let remote_id = RemoteProofId(typed_id.clone().into());
        info!(?proof_id, %typed_id, "proof submitted to remote prover");

        // Store mapping and initial status.
        self.ctx
            .put_remote_proof_id(proof_id, remote_id.clone())
            .await
            .map_err(|e| ProverError::storage("failed to store proof mapping", e))?;

        self.ctx
            .put_status(&remote_id, RemoteProofStatus::Requested)
            .await
            .map_err(|e| ProverError::storage("failed to store initial proof status", e))?;

        Ok(SubmitOutcome::Submitted)
    }
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<H: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> ProverResult<H::ProofId> {
    H::ProofId::try_from(remote_id.0.clone()).map_err(|_| ProverError::RemoteIdDecode)
}

/// Status snapshot for the prover service, surfaced through the
/// [`ServiceMonitor`](strata_service::ServiceMonitor) on
/// [`ProverWorkerHandle`](crate::ProverWorkerHandle).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverStatus {
    /// Number of proofs queued but not yet submitted to the remote prover.
    pub pending: usize,

    /// Most recent block the ASM worker reported as committed, if any.
    pub last_committed: Option<L1BlockCommitment>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use strata_asm_prover_types::L1Range;
    use strata_identifiers::{L1BlockCommitment, L1BlockId};

    use super::*;

    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    fn asm(height: u32) -> ProofId {
        ProofId::Asm(L1Range::single(commitment(height)))
    }

    fn moho(height: u32) -> ProofId {
        ProofId::Moho(commitment(height))
    }

    /// One scripted reply for [`FakeSubmitter`].
    enum FakeResult {
        Outcome(SubmitOutcome),
        Err,
    }

    /// Scriptable [`ProofSubmitter`] for unit tests.
    ///
    /// Returns scripted results in order per `ProofId`. Missing or exhausted
    /// scripts default to [`SubmitOutcome::Submitted`].
    #[derive(Default)]
    struct FakeSubmitter {
        script: HashMap<ProofId, Vec<FakeResult>>,
        call_log: Vec<ProofId>,
    }

    impl FakeSubmitter {
        fn with(mut self, id: ProofId, outcomes: Vec<SubmitOutcome>) -> Self {
            self.script
                .entry(id)
                .or_default()
                .extend(outcomes.into_iter().map(FakeResult::Outcome));
            self
        }

        fn with_err(mut self, id: ProofId) -> Self {
            self.script.entry(id).or_default().push(FakeResult::Err);
            self
        }
    }

    #[async_trait]
    impl ProofSubmitter for FakeSubmitter {
        async fn try_submit(&mut self, id: ProofId) -> ProverResult<SubmitOutcome> {
            self.call_log.push(id);
            let next = self
                .script
                .get_mut(&id)
                .and_then(|v| (!v.is_empty()).then(|| v.remove(0)));
            match next {
                Some(FakeResult::Outcome(o)) => Ok(o),
                Some(FakeResult::Err) => Err(ProverError::NotFound("scripted error")),
                None => Ok(SubmitOutcome::Submitted),
            }
        }
    }

    /// Regression test for the defer-and-drain fix: a Moho proof whose
    /// prerequisite is not yet ready must not consume a capacity slot, so
    /// independent ASM proofs behind it still get submitted in the same tick.
    #[tokio::test]
    async fn deferred_does_not_consume_capacity() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(moho(3));
        queue.enqueue(asm(4));
        queue.enqueue(asm(5));

        let mut submitter = FakeSubmitter::default().with(moho(3), vec![SubmitOutcome::Deferred]);

        schedule_with(&mut queue, &mut submitter, 2).await;

        assert!(submitter.call_log.contains(&asm(4)));
        assert!(submitter.call_log.contains(&asm(5)));
    }

    /// A deferred item is re-enqueued exactly once per scheduling cycle —
    /// never popped twice within the same loop, never lost.
    #[tokio::test]
    async fn deferred_item_reenqueued_exactly_once() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(moho(3));
        queue.enqueue(asm(4));
        queue.enqueue(asm(5));

        let mut submitter = FakeSubmitter::default().with(moho(3), vec![SubmitOutcome::Deferred]);

        schedule_with(&mut queue, &mut submitter, 2).await;

        assert_eq!(
            submitter
                .call_log
                .iter()
                .filter(|&&id| id == moho(3))
                .count(),
            1,
            "deferred item must be popped only once per cycle"
        );
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dequeue_one(), Some(moho(3)));
    }

    /// A `Skipped` outcome (e.g. proof already submitted or already exists)
    /// must not consume a capacity slot either.
    #[tokio::test]
    async fn skipped_does_not_consume_capacity() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(asm(4));

        let mut submitter = FakeSubmitter::default().with(asm(3), vec![SubmitOutcome::Skipped]);

        schedule_with(&mut queue, &mut submitter, 1).await;

        assert_eq!(submitter.call_log, vec![asm(3), asm(4)]);
        assert!(queue.is_empty(), "skipped items are not re-enqueued");
    }

    /// Submission errors are re-enqueued like deferrals, and the next item
    /// still gets a chance to consume the slot.
    #[tokio::test]
    async fn err_treated_like_defer() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(asm(4));

        let mut submitter = FakeSubmitter::default().with_err(asm(3));

        schedule_with(&mut queue, &mut submitter, 1).await;

        assert_eq!(submitter.call_log, vec![asm(3), asm(4)]);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.dequeue_one(), Some(asm(3)));
    }

    #[tokio::test]
    async fn capacity_zero_no_dequeue() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(asm(4));

        let mut submitter = FakeSubmitter::default();

        schedule_with(&mut queue, &mut submitter, 0).await;

        assert!(submitter.call_log.is_empty());
        assert_eq!(queue.len(), 2);
    }

    #[tokio::test]
    async fn drains_when_queue_empty_before_capacity_hit() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(asm(3));
        queue.enqueue(asm(4));

        let mut submitter = FakeSubmitter::default();

        schedule_with(&mut queue, &mut submitter, 10).await;

        assert_eq!(submitter.call_log, vec![asm(3), asm(4)]);
        assert!(queue.is_empty());
    }

    /// Two consecutive cycles: an item deferred in cycle one must be retried
    /// in cycle two with a freshly initialized `deferred` buffer — no state
    /// leaks across calls.
    #[tokio::test]
    async fn deferred_buffer_resets_each_cycle() {
        let mut queue = PendingProofQueue::new();
        queue.enqueue(moho(3));
        queue.enqueue(asm(4));

        // Cycle 1: moho(3) defers, asm(4) submits, moho(3) is re-enqueued.
        let mut submitter = FakeSubmitter::default().with(moho(3), vec![SubmitOutcome::Deferred]);
        schedule_with(&mut queue, &mut submitter, 2).await;

        assert_eq!(submitter.call_log, vec![moho(3), asm(4)]);
        assert_eq!(queue.len(), 1);

        // Cycle 2: moho(3) now succeeds. Reuse the same submitter and queue.
        // The script for moho(3) is exhausted, so it defaults to Submitted.
        queue.enqueue(asm(5));
        schedule_with(&mut queue, &mut submitter, 2).await;

        // moho(3) called once more, asm(5) submitted, queue drained, no stray
        // re-enqueues from the previous cycle.
        assert_eq!(submitter.call_log, vec![moho(3), asm(4), moho(3), asm(5)]);
        assert!(queue.is_empty());
    }
}
