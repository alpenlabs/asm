//! Proof orchestrator — schedules and reconciles remote proof jobs.
//!
//! The orchestrator runs a periodic tick loop that:
//! 1. Reconciles active remote proofs (polls status, stores completed proofs).
//! 2. Schedules new proofs from the pending queue, enforcing prerequisites.

use anyhow::{Context, Result};
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
    /// Drains past proofs whose prerequisites are not yet satisfied (e.g. a Moho
    /// proof waiting on its ASM step proof) so that independent higher-priority
    /// work behind them — typically the next ASM step proof — still gets
    /// submitted within the same tick. Deferred proofs are parked in a local
    /// buffer and re-enqueued at the end to avoid popping the same blocked item
    /// repeatedly within one loop.
    async fn schedule_proofs(&mut self) -> Result<()> {
        let in_flight = self
            .db
            .get_all_in_progress()
            .await
            .context("failed to query in-progress proofs")?
            .len();

        let mut capacity = self.config.max_concurrent_proofs.saturating_sub(in_flight);

        if capacity == 0 {
            return Ok(());
        }

        let mut deferred: Vec<ProofId> = Vec::new();

        while capacity > 0 {
            let Some(proof_id) = self.queue.dequeue_one() else {
                break;
            };
            match self.try_submit(proof_id).await {
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
            self.queue.enqueue(id);
        }

        Ok(())
    }

    /// Attempts to submit a single proof, enforcing prerequisites and dedup.
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
        if proof_store::proof_exists(&self.db, &proof_id).await? {
            debug!(?proof_id, "proof already exists, skipping");
            return Ok(SubmitOutcome::Skipped);
        }

        // Build input and submit to remote prover, dispatching by proof type.
        let typed_id = match &proof_id {
            ProofId::Asm(range) => {
                let runtime_input = self.input_builder.build_asm_runtime_input(range).await?;
                AsmStfProofProgram::start_proving(&runtime_input, &self.asm)
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
                MohoRecursiveProgram::start_proving(&input, &self.moho)
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

/// Outcome of a single `try_submit` call.
enum SubmitOutcome {
    /// Proof was submitted to the remote prover and counts against capacity.
    Submitted,
    /// Proof was already submitted or already exists locally; nothing to do.
    Skipped,
    /// Prerequisites not yet available; caller should re-enqueue for later.
    Deferred,
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<R: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> Result<R::ProofId> {
    R::ProofId::try_from(remote_id.0.clone())
        .map_err(|_| anyhow::anyhow!("failed to decode remote proof ID"))
}
