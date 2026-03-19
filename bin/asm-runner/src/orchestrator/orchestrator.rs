//! Proof orchestrator — schedules and reconciles remote proof jobs.
//!
//! The orchestrator runs a periodic tick loop that:
//! 1. Reconciles active remote proofs (polls status, stores completed proofs).
//! 2. Schedules new proofs from the pending queue, enforcing prerequisites.

use anyhow::{Context, Result};
use strata_asm_proof_db::{ProofDb, RemoteProofMappingDb, RemoteProofStatusDb, SledProofDb};
use strata_asm_proof_types::{AsmProof, MohoProof, ProofId, RemoteProofId};
use tracing::{debug, error, info, warn};
use zkaleido::{ProofType, RemoteProofStatus, ZkVmRemoteProver};

use super::{config::OrchestratorConfig, queue::PendingProofQueue};

/// Orchestrates remote proof generation for ASM and Moho proofs.
pub(crate) struct ProofOrchestrator<R: ZkVmRemoteProver> {
    db: SledProofDb,
    queue: PendingProofQueue,
    remote: R,
    proof_type: ProofType,
    config: OrchestratorConfig,
}

impl<R: ZkVmRemoteProver> ProofOrchestrator<R> {
    /// Creates a new orchestrator.
    pub(crate) fn new(
        db: SledProofDb,
        remote: R,
        proof_type: ProofType,
        config: OrchestratorConfig,
    ) -> Self {
        Self {
            db,
            queue: PendingProofQueue::new(),
            remote,
            proof_type,
            config,
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

        match proof_id {
            ProofId::Asm(range) => {
                info!(?range, "storing completed ASM proof");
                self.db
                    .store_asm_proof(range, AsmProof(receipt))
                    .await
                    .context("failed to store ASM proof")?;
            }
            ProofId::Moho(commitment) => {
                info!(?commitment, "storing completed Moho proof");
                self.db
                    .store_moho_proof(commitment, MohoProof(receipt))
                    .await
                    .context("failed to store Moho proof")?;
            }
        }

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
        if self.proof_exists(&proof_id).await? {
            debug!(?proof_id, "proof already exists, skipping");
            return Ok(());
        }

        // Enforce Moho prerequisites.
        if let ProofId::Moho(commitment) = &proof_id {
            if !self.moho_prerequisites_met(commitment).await? {
                debug!(
                    height = commitment.height(),
                    "Moho prerequisites not met, re-enqueuing"
                );
                self.queue.enqueue(proof_id);
                return Ok(());
            }
        }

        // Prepare host input and submit to remote prover.
        let input = self.prepare_input(&proof_id)?;
        let typed_id = self
            .remote
            .start_proving(input, self.proof_type)
            .await
            .map_err(|e| anyhow::anyhow!("failed to submit proof to remote prover: {e}"))?;

        let remote_id = RemoteProofId(typed_id.clone().into());
        info!(?proof_id, ?remote_id, "proof submitted to remote prover");

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

    /// Prepares host-specific input for the given proof.
    ///
    /// TODO: This requires block data from the chain to build `RuntimeInput`.
    /// For now this is a stub that will be filled in once the block data pipeline
    /// is integrated.
    fn prepare_input(
        &self,
        _proof_id: &ProofId,
    ) -> Result<<R::Input<'_> as zkaleido::ZkVmInputBuilder<'_>>::Input> {
        anyhow::bail!("input preparation not yet implemented — requires block data pipeline")
    }

    /// Returns `true` if the proof already exists in the local proof DB.
    async fn proof_exists(&self, proof_id: &ProofId) -> Result<bool> {
        match proof_id {
            ProofId::Asm(range) => {
                let exists = self
                    .db
                    .get_asm_proof(*range)
                    .await
                    .context("failed to check ASM proof")?
                    .is_some();
                Ok(exists)
            }
            ProofId::Moho(commitment) => {
                let exists = self
                    .db
                    .get_moho_proof(*commitment)
                    .await
                    .context("failed to check Moho proof")?
                    .is_some();
                Ok(exists)
            }
        }
    }

    /// Checks whether the prerequisites for generating `Moho(h)` are met:
    /// 1. `Moho(h-1)` must exist (or this is the first Moho proof).
    /// 2. An ASM proof covering height `h` must exist.
    async fn moho_prerequisites_met(
        &self,
        commitment: &strata_identifiers::L1BlockCommitment,
    ) -> Result<bool> {
        let height = commitment.height();

        // Check that the previous Moho proof exists (unless this is height 0).
        if height > 0 {
            let latest_moho = self
                .db
                .get_latest_moho_proof()
                .await
                .context("failed to query latest Moho proof")?;

            match latest_moho {
                Some((latest_commitment, _)) => {
                    if latest_commitment.height() < height - 1 {
                        return Ok(false);
                    }
                }
                None => return Ok(false),
            }
        }

        // Check that an ASM proof covering this height exists.
        // TODO: support range-based ASM proof lookup.
        let asm_range = strata_asm_proof_types::L1Range::single(*commitment);
        let asm_exists = self
            .db
            .get_asm_proof(asm_range)
            .await
            .context("failed to check ASM proof for Moho prerequisite")?
            .is_some();

        Ok(asm_exists)
    }
}

/// Converts a persisted [`RemoteProofId`] back into the host's typed proof ID.
fn to_typed_proof_id<R: ZkVmRemoteProver>(remote_id: &RemoteProofId) -> Result<R::ProofId> {
    R::ProofId::try_from(remote_id.0.clone())
        .map_err(|_| anyhow::anyhow!("failed to decode remote proof ID"))
}
