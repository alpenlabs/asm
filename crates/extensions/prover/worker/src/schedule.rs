//! Scheduling of pending proofs onto the remote prover.
//!
//! Each tick, the service computes the remaining submission capacity and drains
//! the pending queue up to that many real submissions. The loop control flow
//! ([`schedule_with`]) is separated from the actual submission
//! ([`ProofSubmitter`]) so it can be unit-tested with a fake submitter.

use async_trait::async_trait;
use moho_recursive_proof::MohoRecursiveProgram;
use strata_asm_proof_impl::program::AsmStfProofProgram;
use strata_asm_prover_types::{ProofId, RemoteProofId};
use tracing::{debug, info, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost, ZkVmRemoteProgram};

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
    input::InputBuilder,
    proof_store,
    queue::PendingProofQueue,
    state::ProverServiceState,
};

/// Dequeues proofs from the pending queue and submits them to the remote prover.
///
/// Computes the available submission capacity, then delegates the loop control
/// flow to [`schedule_with`] through a short-lived [`StateSubmitter`] so the
/// scheduling loop itself can be unit-tested with a fake submitter.
pub(crate) async fn schedule_proofs<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
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
