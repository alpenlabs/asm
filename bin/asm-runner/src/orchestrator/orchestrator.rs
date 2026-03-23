//! Proof orchestrator — schedules and reconciles remote proof jobs.
//!
//! The orchestrator runs a periodic tick loop that:
//! 1. Reconciles active remote proofs (polls status, stores completed proofs).
//! 2. Schedules new proofs from the pending queue, enforcing prerequisites.

use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoind_async_client::{traits::Reader, Client};
use moho_runtime_impl::RuntimeInput;
use moho_runtime_interface::MohoProgram;
use strata_asm_proof_db::{ProofDb, RemoteProofMappingDb, RemoteProofStatusDb, SledProofDb};
use strata_asm_proof_impl::moho_program::{input::L1Block, program::AsmStfProgram};
use strata_asm_proof_types::{AsmProof, L1Range, MohoProof, ProofId, RemoteProofId};
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_identifiers::L1BlockCommitment;
use strata_storage::AsmStateManager;
use tracing::{debug, error, info, warn};
use zkaleido::{ProofType, RemoteProofStatus, ZkVmProgram, ZkVmRemoteProver};

use super::{config::OrchestratorConfig, queue::PendingProofQueue};

/// Orchestrates remote proof generation for ASM and Moho proofs.
pub(crate) struct ProofOrchestrator<R: ZkVmRemoteProver> {
    db: SledProofDb,
    queue: PendingProofQueue,
    remote: R,
    proof_type: ProofType,
    config: OrchestratorConfig,
    asm_manager: Arc<AsmStateManager>,
    bitcoin_client: Arc<Client>,
}

impl<R: ZkVmRemoteProver> ProofOrchestrator<R> {
    /// Creates a new orchestrator.
    pub(crate) fn new(
        db: SledProofDb,
        remote: R,
        proof_type: ProofType,
        config: OrchestratorConfig,
        asm_manager: Arc<AsmStateManager>,
        bitcoin_client: Arc<Client>,
    ) -> Self {
        Self {
            db,
            queue: PendingProofQueue::new(),
            remote,
            proof_type,
            config,
            asm_manager,
            bitcoin_client,
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

        // Build the RuntimeInput and prepare host-specific input.
        let runtime_input = self.build_runtime_input(&proof_id).await?;
        let input = strata_asm_proof_impl::program::AsmStfProofProgram::prepare_input::<
            R::Input<'_>,
        >(&runtime_input)
        .map_err(|e| anyhow::anyhow!("failed to prepare ZkVM input: {e}"))?;

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

    // ---- Input preparation ------------------------------------------------

    /// Builds the [`RuntimeInput`] for the given proof.
    async fn build_runtime_input(&self, proof_id: &ProofId) -> Result<RuntimeInput> {
        match proof_id {
            ProofId::Asm(range) => self.build_asm_runtime_input(range).await,
            ProofId::Moho(_) => {
                anyhow::bail!("Moho input preparation not yet implemented")
            }
        }
    }

    /// Builds the [`RuntimeInput`] for a single-block ASM proof.
    ///
    /// This fetches the Bitcoin block and auxiliary data, reconstructs the
    /// pre-state, and assembles the input the ZkVM program expects.
    async fn build_asm_runtime_input(&self, range: &L1Range) -> Result<RuntimeInput> {
        let commitment = range.start();

        // 1. Fetch the Bitcoin block.
        let block_hash = commitment.blkid().to_block_hash();
        let block = self
            .bitcoin_client
            .get_block(&block_hash)
            .await
            .context("failed to fetch Bitcoin block")?;

        // 2. Fetch the auxiliary data stored during STF execution.
        let aux_data = self
            .asm_manager
            .get_aux_data(commitment)
            .context("failed to fetch aux data")?
            .context("aux data not found for block")?;

        // 3. Build the step input.
        let step_input = strata_asm_proof_impl::moho_program::input::AsmStepInput {
            block: L1Block(block.clone()),
            aux_data,
        };

        // 4. Fetch the pre-state (anchor state for the parent block).
        let parent_hash = block.header.prev_blockhash;
        let parent_height = commitment
            .height()
            .checked_sub(1)
            .context("cannot generate ASM proof for height 0 — no parent block")?;
        let parent_commitment =
            L1BlockCommitment::new(parent_height, parent_hash.to_l1_block_id());

        let asm_state = self
            .asm_manager
            .get_state(parent_commitment)
            .context("failed to fetch parent anchor state")?
            .context("parent anchor state not found")?;
        let anchor_state = asm_state.state();

        // 5. Compute the Moho pre-state from the anchor state.
        let inner_state_commitment = AsmStfProgram::compute_state_commitment(anchor_state);
        let moho_pre_state = moho_types::MohoState::new(
            inner_state_commitment,
            strata_predicate::PredicateKey::always_accept(),
            moho_types::ExportState::new(vec![]),
        );

        // 6. Build RuntimeInput.
        let runtime_input = RuntimeInput::new(
            moho_pre_state,
            borsh::to_vec(anchor_state).context("failed to borsh-encode anchor state")?,
            borsh::to_vec(&step_input).context("failed to borsh-encode step input")?,
        );

        Ok(runtime_input)
    }

    // ---- Helpers ----------------------------------------------------------

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
    async fn moho_prerequisites_met(&self, commitment: &L1BlockCommitment) -> Result<bool> {
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
        let asm_range = L1Range::single(*commitment);
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
