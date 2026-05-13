//! Proof orchestrator — schedules and reconciles remote proof jobs.
//!
//! The orchestrator runs a periodic tick loop that:
//! 1. Reconciles active remote proofs (polls status, stores completed proofs).
//! 2. Schedules new proofs from the pending queue, enforcing prerequisites.

use anyhow::{Context, Result};
use async_trait::async_trait;
use moho_recursive_proof::MohoRecursiveProgram;
use strata_asm_proof_db::{RemoteProofMappingDb, RemoteProofStatusDb, SledProofDb};
use strata_asm_proof_impl::program::AsmStfProofProgram;
use strata_asm_proof_types::{ProofId, RemoteProofId};
use strata_tasks::ShutdownGuard;
use tokio::{sync::mpsc, time};
use tracing::{debug, error, info, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost, ZkVmRemoteProgram};

use super::{
    config::OrchestratorConfig, input::InputBuilder, proof_store, queue::PendingProofQueue,
};

/// Orchestrates remote proof generation for ASM and Moho proofs.
pub(crate) struct ProofOrchestrator<Host: ZkVmRemoteHost> {
    db: SledProofDb,
    queue: PendingProofQueue,
    rx: mpsc::UnboundedReceiver<ProofId>,
    asm: Host,
    moho: Host,
    config: OrchestratorConfig,
    input_builder: InputBuilder,
}

impl<R: ZkVmRemoteHost> ProofOrchestrator<R> {
    /// Creates a new orchestrator.
    pub(crate) fn new(
        db: SledProofDb,
        asm: R,
        moho: R,
        config: OrchestratorConfig,
        input_builder: InputBuilder,
        rx: mpsc::UnboundedReceiver<ProofId>,
    ) -> Self {
        Self {
            db,
            queue: PendingProofQueue::new(),
            rx,
            asm,
            moho,
            config,
            input_builder,
        }
    }

    /// Runs the orchestrator loop until shutdown is requested or the channel is closed.
    pub(crate) async fn run(&mut self, shutdown: ShutdownGuard) -> Result<()> {
        info!("proof orchestrator started");
        loop {
            if let Err(e) = self.tick().await {
                error!(?e, "orchestrator tick failed");
            }

            if shutdown.should_shutdown() {
                info!("proof orchestrator shutting down");
                return Ok(());
            }

            // Exit once the sender side has been dropped (shutdown) and there is
            // nothing left to process.
            if self.rx.is_closed() && self.queue.is_empty() {
                info!("proof orchestrator shutting down");
                return Ok(());
            }

            tokio::select! {
                _ = shutdown.wait_for_shutdown() => {
                    info!("proof orchestrator shutting down");
                    return Ok(());
                }
                _ = time::sleep(self.config.tick_interval) => {}
            }
        }
    }

    /// Drains incoming proof requests from the channel into the pending queue.
    fn drain_incoming(&mut self) {
        while let Ok(id) = self.rx.try_recv() {
            debug!(?id, "received proof request");
            self.queue.enqueue(id);
        }
    }

    /// Executes one orchestration cycle.
    async fn tick(&mut self) -> Result<()> {
        self.drain_incoming();

        if !self.queue.is_empty() {
            debug!(pending = self.queue.len(), "orchestrator tick");
        }

        self.reconcile_active_proofs().await?;
        self.schedule_proofs().await?;
        Ok(())
    }

    // ---- Step 1: Reconcile ------------------------------------------------

    /// Polls all in-progress remote proofs and stores any that have completed.
    async fn reconcile_active_proofs(&mut self) -> Result<()> {
        let in_progress = self
            .db
            .get_all_in_progress()
            .await
            .context("failed to query in-progress proofs")?;

        for (remote_id, old_status) in in_progress {
            if let Err(e) = self.reconcile_one(&remote_id, &old_status).await {
                warn!(?remote_id, ?e, "failed to reconcile remote proof");
            }
        }
        Ok(())
    }

    /// Reconciles a single remote proof.
    async fn reconcile_one(
        &self,
        remote_id: &RemoteProofId,
        old_status: &RemoteProofStatus,
    ) -> Result<()> {
        let typed_id = to_typed_proof_id::<R>(remote_id)?;

        // NOTE: We use `self.asm` here but this could be any `ZkVmRemoteHost` instance.
        // `get_status` only requires a network client and proof ID — not the ELF or
        // proving key. Since the orchestrator is generic over a single `R: ZkVmRemoteHost`,
        // both `asm` and `moho` share the same concrete type, so either works.
        let new_status = self
            .asm
            .get_status(&typed_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to query remote proof status: {e}"))?;

        if &new_status == old_status {
            return Ok(());
        }

        debug!(
            %remote_id,
            ?old_status,
            ?new_status,
            "remote proof status changed"
        );

        match &new_status {
            RemoteProofStatus::Completed => {
                self.handle_completed(remote_id, &typed_id).await?;
            }
            RemoteProofStatus::Failed(reason) => {
                error!(?remote_id, %reason, "remote proof generation failed");
                self.db
                    .remove(remote_id)
                    .await
                    .context("failed to remove failed proof status")?;
            }
            _ => {
                self.db
                    .update_status(remote_id, new_status)
                    .await
                    .context("failed to update proof status")?;
            }
        }
        Ok(())
    }

    /// Retrieves a completed proof and stores it in the proof DB.
    async fn handle_completed(
        &self,
        remote_id: &RemoteProofId,
        typed_id: &R::ProofId,
    ) -> Result<()> {
        // NOTE: We use `self.asm` here but this could be any `ZkVmRemoteHost` instance.
        // `get_proof` only requires a network client and proof ID — not the ELF or
        // proving key. Since the orchestrator is generic over a single `R: ZkVmRemoteHost`,
        // both `asm` and `moho` share the same concrete type, so either works.
        let receipt = self
            .asm
            .get_proof(typed_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to retrieve completed proof: {e}"))?;

        let proof_id = self
            .db
            .get_proof_id(remote_id)
            .await
            .context("failed to look up proof ID from remote ID")?
            .context("no mapping found for completed remote proof")?;

        proof_store::store_completed_proof(&self.db, proof_id, receipt).await?;

        self.db
            .remove(remote_id)
            .await
            .context("failed to remove completed proof status")?;

        Ok(())
    }

    // ---- Step 2: Schedule -------------------------------------------------

    /// Dequeues proofs from the pending queue and submits them to the remote prover.
    ///
    /// Computes the available submission capacity, then delegates the loop
    /// control flow to [`schedule_with`] through a short-lived
    /// [`OrchestratorSubmitter`] so the scheduling loop itself can be
    /// unit-tested with a fake submitter.
    async fn schedule_proofs(&mut self) -> Result<()> {
        let in_flight = self
            .db
            .get_all_in_progress()
            .await
            .context("failed to query in-progress proofs")?
            .len();

        let capacity = self.config.max_concurrent_proofs.saturating_sub(in_flight);
        if capacity == 0 {
            return Ok(());
        }

        let mut submitter = OrchestratorSubmitter {
            db: &self.db,
            asm: &self.asm,
            moho: &self.moho,
            input_builder: &self.input_builder,
        };
        schedule_with(&mut self.queue, &mut submitter, capacity).await;
        Ok(())
    }
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
///
/// `?Send` because `zkaleido::ZkVmRemoteProver` is itself declared
/// `#[async_trait(?Send)]` upstream — its async methods (e.g. `start_proving`)
/// return non-`Send` futures to accommodate backends whose clients hold
/// non-`Send` state across `.await`. Awaiting them here transitively makes
/// `try_submit` non-`Send`. This is fine because the orchestrator is driven
/// from a `LocalSet` (see `bootstrap.rs`).
#[async_trait(?Send)]
trait ProofSubmitter {
    async fn try_submit(&mut self, proof_id: ProofId) -> Result<SubmitOutcome>;
}

/// Runs the scheduling loop: pulls items from `queue` and submits via
/// `submitter` until either `capacity` real submissions have been issued or
/// the queue drains.
///
/// Drains past proofs whose prerequisites are not yet satisfied (e.g. a Moho
/// proof waiting on its ASM step proof) so that independent higher-priority
/// work behind them — typically the next ASM step proof — still gets submitted
/// within the same tick. Deferred proofs (and submission errors) are parked in
/// a local buffer and re-enqueued at the end, so the same blocked item is not
/// popped twice within one loop. All submission errors are absorbed and
/// logged; the function does not surface them upward.
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

/// [`ProofSubmitter`] backed by the orchestrator's DB, hosts, and input
/// builder. Constructed inline by [`ProofOrchestrator::schedule_proofs`] for
/// the duration of one scheduling cycle.
struct OrchestratorSubmitter<'a, R: ZkVmRemoteHost> {
    db: &'a SledProofDb,
    asm: &'a R,
    moho: &'a R,
    input_builder: &'a InputBuilder,
}

#[async_trait(?Send)]
impl<R: ZkVmRemoteHost> ProofSubmitter for OrchestratorSubmitter<'_, R> {
    async fn try_submit(&mut self, proof_id: ProofId) -> Result<SubmitOutcome> {
        // Skip if already submitted.
        if self
            .db
            .get_remote_proof_id(proof_id)
            .await
            .context("failed to check remote proof mapping")?
            .is_some()
        {
            debug!(?proof_id, "proof already submitted, skipping");
            return Ok(SubmitOutcome::Skipped);
        }

        // Skip if proof already exists locally.
        if proof_store::proof_exists(self.db, &proof_id).await? {
            debug!(?proof_id, "proof already exists, skipping");
            return Ok(SubmitOutcome::Skipped);
        }

        // Build input and submit to remote prover, dispatching by proof type.
        let typed_id = match &proof_id {
            ProofId::Asm(range) => {
                let runtime_input = self.input_builder.build_asm_runtime_input(range).await?;
                AsmStfProofProgram::start_proving(&runtime_input, self.asm)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to submit proof to remote prover: {e}"))?
            }
            ProofId::Moho(block) => {
                let prerequisite = match self.input_builder.check_moho_prerequisite(*block).await {
                    Ok(prereq) => prereq,
                    Err(e) => {
                        debug!(?proof_id, %e, "moho prerequisite not ready, deferring");
                        return Ok(SubmitOutcome::Deferred);
                    }
                };
                let input = self
                    .input_builder
                    .build_moho_runtime_input(prerequisite, *block)
                    .await?;
                MohoRecursiveProgram::start_proving(&input, self.moho)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to submit proof to remote prover: {e}"))?
            }
        };

        let remote_id = RemoteProofId(typed_id.clone().into());
        info!(?proof_id, %typed_id, "proof submitted to remote prover");

        // Store mapping and initial status.
        self.db
            .put_remote_proof_id(proof_id, remote_id.clone())
            .await
            .context("failed to store proof mapping")?;

        self.db
            .put_status(&remote_id, RemoteProofStatus::Requested)
            .await
            .context("failed to store initial proof status")?;

        Ok(SubmitOutcome::Submitted)
    }
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<R: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> Result<R::ProofId> {
    R::ProofId::try_from(remote_id.0.clone())
        .map_err(|_| anyhow::anyhow!("failed to decode remote proof ID"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use strata_asm_proof_types::L1Range;
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

    #[async_trait(?Send)]
    impl ProofSubmitter for FakeSubmitter {
        async fn try_submit(&mut self, id: ProofId) -> Result<SubmitOutcome> {
            self.call_log.push(id);
            let next = self
                .script
                .get_mut(&id)
                .and_then(|v| (!v.is_empty()).then(|| v.remove(0)));
            match next {
                Some(FakeResult::Outcome(o)) => Ok(o),
                Some(FakeResult::Err) => Err(anyhow::anyhow!("scripted error")),
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
