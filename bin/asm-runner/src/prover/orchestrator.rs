//! Proof orchestrator — schedules and reconciles remote proof jobs.
//!
//! The orchestrator runs a periodic tick loop that:
//! 1. Reconciles active remote proofs (polls status, stores completed proofs).
//! 2. Schedules new proofs from the pending queue, enforcing prerequisites.

use anyhow::{Context, Result};
use strata_asm_proof_db::{RemoteProofMappingDb, RemoteProofStatusDb, SledProofDb};
use strata_asm_proof_impl::program::AsmStfProofProgram;
use strata_asm_proof_types::{ProofId, RemoteProofId};
use tracing::{debug, error, info, warn};
use zkaleido::{RemoteProofStatus, ZkVmRemoteHost, ZkVmRemoteProgram};

use super::{
    config::OrchestratorConfig, input::InputBuilder, proof_store, queue::PendingProofQueue,
};

/// Orchestrates remote proof generation for ASM proofs.
pub(crate) struct ProofOrchestrator<R: ZkVmRemoteHost> {
    db: SledProofDb,
    queue: PendingProofQueue,
    remote: R,
    config: OrchestratorConfig,
    input_builder: InputBuilder,
}

impl<R: ZkVmRemoteHost> ProofOrchestrator<R> {
    /// Creates a new orchestrator.
    pub(crate) fn new(
        db: SledProofDb,
        remote: R,
        config: OrchestratorConfig,
        input_builder: InputBuilder,
    ) -> Self {
        Self {
            db,
            queue: PendingProofQueue::new(),
            remote,
            config,
            input_builder,
        }
    }

    /// Enqueues a proof for generation.
    pub(crate) fn enqueue(&mut self, id: ProofId) {
        self.queue.enqueue(id);
    }

    /// Runs the orchestrator loop until the future is cancelled.
    pub(crate) async fn run(&mut self) -> Result<()> {
        info!("proof orchestrator started");
        loop {
            if let Err(e) = self.tick().await {
                error!(?e, "orchestrator tick failed");
            }
            tokio::time::sleep(self.config.tick_interval).await;
        }
    }

    /// Executes one orchestration cycle.
    async fn tick(&mut self) -> Result<()> {
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

        let new_status = self
            .remote
            .get_status(&typed_id)
            .await
            .map_err(|e| anyhow::anyhow!("failed to query remote proof status: {e}"))?;

        if &new_status == old_status {
            return Ok(());
        }

        debug!(
            ?remote_id,
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
        let receipt = self
            .remote
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
    async fn schedule_proofs(&mut self) -> Result<()> {
        let in_flight = self
            .db
            .get_all_in_progress()
            .await
            .context("failed to query in-progress proofs")?
            .len();

        let capacity = self
            .config
            .max_concurrent_asm_proofs
            .saturating_sub(in_flight);

        if capacity == 0 {
            return Ok(());
        }

        let batch = self.queue.dequeue_batch(capacity);
        for proof_id in batch {
            if let Err(e) = self.try_submit(proof_id).await {
                warn!(?proof_id, ?e, "failed to submit proof");
            }
        }
        Ok(())
    }

    /// Attempts to submit a single proof, enforcing prerequisites and dedup.
    async fn try_submit(&mut self, proof_id: ProofId) -> Result<()> {
        // Skip if already submitted.
        if self
            .db
            .get_remote_proof_id(proof_id)
            .await
            .context("failed to check remote proof mapping")?
            .is_some()
        {
            debug!(?proof_id, "proof already submitted, skipping");
            return Ok(());
        }

        // Skip if proof already exists locally.
        if proof_store::proof_exists(&self.db, &proof_id).await? {
            debug!(?proof_id, "proof already exists, skipping");
            return Ok(());
        }

        // Build input and submit to remote prover, dispatching by proof type.
        let typed_id = match &proof_id {
            ProofId::Asm(range) => {
                let runtime_input =
                    self.input_builder.build_asm_runtime_input(range).await?;
                AsmStfProofProgram::start_proving(&runtime_input, &self.remote)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("failed to submit proof to remote prover: {e}")
                    })?
            }
            ProofId::Moho(_) => {
                debug!(?proof_id, "Moho proof generation not yet supported, skipping");
                return Ok(());
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

        Ok(())
    }
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<R: ZkVmRemoteHost>(remote_id: &RemoteProofId) -> Result<R::ProofId> {
    R::ProofId::try_from(remote_id.0.clone())
        .map_err(|_| anyhow::anyhow!("failed to decode remote proof ID"))
}
