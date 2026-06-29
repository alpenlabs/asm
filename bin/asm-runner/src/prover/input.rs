//! Input preparation for proof generation.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type.

use std::sync::Arc;

use anyhow::{Context, Result};
use asm_storage::{SledAsmAuxDataDb, SledAsmStateDb};
use bitcoind_async_client::{Client, traits::Reader};
use moho_recursive_proof::{MohoRecursiveInput, MohoRecursiveOutput};
use moho_runtime_impl::RuntimeInput;
use moho_types::{MohoState, RecursiveMohoProof, StepMohoAttestation, StepMohoProof};
use ssz::{Decode, Encode};
use strata_asm_proof_db::{MohoStateDb, ProofDb, SledMohoStateDb, SledProofDb};
use strata_asm_proof_impl::moho_program::input::AsmStepInput;
use strata_asm_proof_types::L1Range;
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_btc_verification::{self, TxidInclusionProof};
use strata_identifiers::L1BlockCommitment;
use strata_merkle::{BinaryMerkleTree, MerkleProofB32, Sha256NoPrefixHasher};
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher as TreeSha256Hasher, TreeHash};

/// Builds [`RuntimeInput`] for proof generation, dispatching by proof type.
pub(crate) struct InputBuilder {
    state_db: Arc<SledAsmStateDb>,
    aux_db: Arc<SledAsmAuxDataDb>,
    bitcoin_client: Arc<Client>,
    proof_db: SledProofDb,
    moho_state_db: SledMohoStateDb,
    genesis: L1BlockCommitment,
    asm_predicate: PredicateKey,
    moho_predicate: PredicateKey,
}

pub(crate) struct MohoPrerequisite {
    prev_moho_proof: Option<RecursiveMohoProof>,
    incremental_step_proof: StepMohoProof,
}

impl InputBuilder {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor wires every dependency proof input building needs; one call site"
    )]
    pub(crate) fn new(
        state_db: Arc<SledAsmStateDb>,
        aux_db: Arc<SledAsmAuxDataDb>,
        bitcoin_client: Arc<Client>,
        proof_db: SledProofDb,
        moho_state_db: SledMohoStateDb,
        genesis: L1BlockCommitment,
        asm_predicate: PredicateKey,
        moho_predicate: PredicateKey,
    ) -> Self {
        Self {
            state_db,
            aux_db,
            bitcoin_client,
            proof_db,
            moho_state_db,
            genesis,
            asm_predicate,
            moho_predicate,
        }
    }

    async fn get_parent_commitment(&self, l1_ref: L1BlockCommitment) -> Result<L1BlockCommitment> {
        let block_hash = l1_ref.blkid().to_block_hash();
        let header = self
            .bitcoin_client
            .get_block_header(&block_hash)
            .await
            .context("failed to fetch Bitcoin block")?;
        let parent_hash = header.prev_blockhash;

        let parent_height = l1_ref
            .height()
            .checked_sub(1)
            .context("cannot generate ASM proof for height 0 — no parent block")?;

        let parent = L1BlockCommitment::new(parent_height, parent_hash.to_l1_block_id());
        Ok(parent)
    }

    /// Fetches the persisted [`MohoState`] for the given L1 block. The worker
    /// materializes this alongside each anchor state — see `AsmWorkerContext::store_anchor_state`.
    async fn get_moho_state(&self, l1_ref: L1BlockCommitment) -> Result<MohoState> {
        self.moho_state_db
            .get_moho_state(l1_ref)
            .await
            .context("failed to fetch moho state")?
            .context("moho state not found for block")
    }

    /// Returns the worker-processed L1 blocks that may still need proofs after a
    /// restart: every persisted anchor on the *canonical* chain above the highest
    /// canonical block that already has a Moho proof, and above genesis.
    ///
    /// The in-memory pending queue is rebuilt from this on startup. The proof
    /// request channel only re-delivers requests for blocks the worker
    /// *reprocesses*, and an already-processed block is a no-op — so a proof
    /// that was pending (enqueued but not yet submitted, e.g. a Moho proof
    /// deferred on a missing prerequisite) at restart time would otherwise be
    /// lost, permanently stalling the recursive Moho chain behind the gap.
    ///
    /// The watermark must be derived along the canonical chain, *not* from the
    /// global-maximum Moho proof. Orphaned states and proofs from abandoned reorg
    /// branches are never pruned (see
    /// [`AnchorStateStore::get_latest_asm_state`](strata_asm_worker::AnchorStateStore::get_latest_asm_state)),
    /// so an orphaned branch's proof can outrank the canonical proof frontier;
    /// trusting the global max would skip the genuinely-pending canonical blocks
    /// below it and stall their Moho chain forever. Instead we walk the canonical
    /// L1 ancestry downward and stop at the first block that already has a Moho
    /// proof: since `Moho(H)` is only submitted once `Moho(H-1)` and `Asm(H)` are
    /// stored, a canonical proof at height H implies every canonical proof at or
    /// below H is done. `try_submit` drops any re-enqueued proof that turns out
    /// to already exist or be in flight.
    pub(crate) async fn proofs_to_backfill(&self) -> Result<Vec<L1BlockCommitment>> {
        let genesis_height = self.genesis.height();

        // Highest persisted anchor. May belong to an abandoned reorg branch, so
        // it only bounds the walk — canonicality is established per height below.
        let Some(latest) = self.state_db.get_latest()? else {
            return Ok(Vec::new());
        };
        let latest_height = latest.chain_view.pow_state.last_verified_block.height();

        // Clamp to the canonical tip: after a reorg to a shorter chain the
        // highest persisted block can outrank the current L1 tip, and
        // `get_block_hash` would fail for a height bitcoind no longer has.
        let tip_height = self
            .bitcoin_client
            .get_block_count()
            .await
            .context("failed to fetch L1 block count")?;
        let mut height = latest_height.min(u32::try_from(tip_height).unwrap_or(u32::MAX));

        let mut backfill = Vec::new();
        while height > genesis_height {
            let block_hash = self
                .bitcoin_client
                .get_block_hash(u64::from(height))
                .await
                .with_context(|| format!("failed to fetch canonical block hash at {height}"))?;
            let commitment = L1BlockCommitment::new(height, block_hash.to_l1_block_id());

            // Heights above the processed tip are not yet persisted; the worker
            // re-processes and re-enqueues them on sync, so recovery skips them.
            if self.state_db.contains(&commitment)? {
                if self.proof_db.get_moho_proof(commitment).await?.is_some() {
                    break;
                }
                backfill.push(commitment);
            }

            height -= 1;
        }

        // Oldest-first, the order the recursive Moho chain needs.
        backfill.reverse();
        Ok(backfill)
    }

    pub(crate) async fn check_moho_prerequisite(
        &self,
        block: L1BlockCommitment,
    ) -> Result<MohoPrerequisite> {
        // 1. ASM step proof is required.
        let asm_proof = self
            .proof_db
            .get_asm_proof(L1Range::single(block))
            .await?
            .context("ASM step proof not available yet for this block")?;

        let asm_receipt = asm_proof.0.receipt();
        let asm_attestation =
            StepMohoAttestation::from_ssz_bytes(asm_receipt.public_values().as_bytes())
                .context("invalid ASM attestation in stored proof")?;
        let asm_step_proof =
            StepMohoProof::new(asm_attestation, asm_receipt.proof().as_bytes().to_vec());

        // 2. Previous moho proof: required unless this is the genesis block.
        let parent = self.get_parent_commitment(block).await?;
        let prev_moho_proof = if parent == self.genesis {
            None
        } else {
            let proof = self
                .proof_db
                .get_moho_proof(parent)
                .await?
                .context("previous moho recursive proof not available yet")?;
            let receipt = proof.0.receipt();
            let output = MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
                .context("invalid moho recursive output in stored proof")?;
            Some(RecursiveMohoProof::new(
                output.attestation().clone(),
                receipt.proof().as_bytes().to_vec(),
            ))
        };

        Ok(MohoPrerequisite {
            incremental_step_proof: asm_step_proof,
            prev_moho_proof,
        })
    }

    /// Builds the [`RuntimeInput`] for a single-block ASM proof.
    ///
    /// This fetches the Bitcoin block and auxiliary data, reconstructs the
    /// pre-state, and assembles the input the ZkVM program expects.
    pub(crate) async fn build_asm_runtime_input(&self, range: &L1Range) -> Result<RuntimeInput> {
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
            .aux_db
            .get(&commitment)
            .context("failed to fetch aux data")?
            .context("aux data not found for block")?;

        let coinbase_inclusion_proof = match block.witness_root() {
            Some(_) => Some(TxidInclusionProof::generate(&block.txdata, 0)),
            None => None,
        };

        // 3. Build the step input.
        let step_input = AsmStepInput::new(block.clone(), aux_data, coinbase_inclusion_proof);

        // 4. Fetch the pre-state (anchor state for the parent block).
        let parent_commitment = self.get_parent_commitment(commitment).await?;

        let anchor_state = self
            .state_db
            .get(&parent_commitment)
            .context("failed to fetch parent anchor state")?
            .context("parent anchor state not found")?;

        // 5. Compute the Moho pre-state from the anchor state.
        let moho_pre_state = self.get_moho_state(parent_commitment).await?;

        // 6. Build RuntimeInput.
        let runtime_input = RuntimeInput::new(
            moho_pre_state,
            anchor_state.as_ssz_bytes(),
            step_input.as_ssz_bytes(),
        );

        Ok(runtime_input)
    }

    pub(crate) async fn build_moho_runtime_input(
        &self,
        prerequisite: MohoPrerequisite,
        l1_ref: L1BlockCommitment,
    ) -> Result<MohoRecursiveInput> {
        let moho_predicate = self.moho_predicate.clone();

        let MohoPrerequisite {
            prev_moho_proof,
            incremental_step_proof,
        } = prerequisite;

        // The inner step proof is the ASM STF proof, so the step predicate is
        // the ASM predicate.
        let step_predicate = self.asm_predicate.clone();

        let parent = self.get_parent_commitment(l1_ref).await?;
        let parent_state = self.get_moho_state(parent).await?;

        let leaves = vec![
            <_ as TreeHash>::tree_hash_root::<TreeSha256Hasher>(&parent_state.inner_state)
                .into_inner(),
            <_ as TreeHash>::tree_hash_root::<TreeSha256Hasher>(&parent_state.next_predicate)
                .into_inner(),
            <_ as TreeHash>::tree_hash_root::<TreeSha256Hasher>(&parent_state.export_state)
                .into_inner(),
            [0u8; 32],
        ];

        let generic_proof = BinaryMerkleTree::from_leaves::<Sha256NoPrefixHasher>(leaves)
            .expect("valid tree")
            .gen_proof(1)
            .expect("proof exists");
        let step_predicate_merkle_proof = MerkleProofB32::from_generic(&generic_proof);

        Ok(MohoRecursiveInput::new(
            moho_predicate,
            prev_moho_proof,
            incremental_step_proof,
            step_predicate,
            step_predicate_merkle_proof,
        ))
    }
}
