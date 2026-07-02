//! Input preparation for proof generation.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type,
//! reading every dependency (proofs, Moho state, anchor state, aux data, L1
//! blocks) through the [`ProverContext`] rather than holding concrete handles.

use moho_recursive_proof::{MohoRecursiveInput, MohoRecursiveOutput};
use moho_runtime_impl::RuntimeInput;
use moho_types::{MohoState, RecursiveMohoProof, StepMohoAttestation, StepMohoProof};
use ssz::{Decode, Encode};
use strata_asm_proof_impl::moho_program::input::AsmStepInput;
use strata_asm_prover_types::L1Range;
use strata_btc_types::BlockHashExt;
use strata_btc_verification::TxidInclusionProof;
use strata_identifiers::L1BlockCommitment;
use strata_merkle::{BinaryMerkleTree, MerkleProofB32, Sha256NoPrefixHasher};
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher as TreeSha256Hasher, TreeHash};

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
};

/// Builds [`RuntimeInput`] for proof generation, dispatching by proof type.
///
/// Holds only the values that are fixed for the lifetime of the prover (the
/// genesis commitment and the two predicate keys); all per-block data is read
/// from the [`ProverContext`] passed to each method.
#[derive(Debug)]
pub struct InputBuilder {
    genesis: L1BlockCommitment,
    asm_predicate: PredicateKey,
    moho_predicate: PredicateKey,
}

/// Prerequisites required to build a Moho recursive proof input for a block:
/// the inner ASM step proof and (unless genesis) the previous Moho proof.
#[derive(Debug)]
pub struct MohoPrerequisite {
    prev_moho_proof: Option<RecursiveMohoProof>,
    incremental_step_proof: StepMohoProof,
}

impl InputBuilder {
    /// Creates a new input builder.
    pub fn new(
        genesis: L1BlockCommitment,
        asm_predicate: PredicateKey,
        moho_predicate: PredicateKey,
    ) -> Self {
        Self {
            genesis,
            asm_predicate,
            moho_predicate,
        }
    }

    async fn get_parent_commitment<C: ProverContext>(
        &self,
        ctx: &C,
        l1_ref: L1BlockCommitment,
    ) -> ProverResult<L1BlockCommitment> {
        let header = ctx.get_l1_block_header(l1_ref.blkid()).await?;
        let parent_hash = header.prev_blockhash;

        let parent_height = l1_ref.height().checked_sub(1).ok_or(ProverError::NotFound(
            "cannot generate ASM proof for height 0 — no parent block",
        ))?;

        let parent = L1BlockCommitment::new(parent_height, parent_hash.to_l1_block_id());
        Ok(parent)
    }

    /// Fetches the persisted [`MohoState`] for the given L1 block. The worker
    /// materializes this alongside each anchor state — see the runner's
    /// `AsmWorkerContext::store_anchor_state`.
    async fn get_moho_state<C: ProverContext>(
        &self,
        ctx: &C,
        l1_ref: L1BlockCommitment,
    ) -> ProverResult<MohoState> {
        ctx.get_moho_state(l1_ref)
            .await
            .map_err(|e| ProverError::storage("failed to fetch moho state", e))?
            .ok_or(ProverError::NotFound("moho state not found for block"))
    }

    /// Returns the worker-processed L1 blocks that may still need proofs after a
    /// restart: every persisted anchor on the *canonical* chain above the highest
    /// canonical block that already has a Moho proof, and above genesis.
    ///
    /// The in-memory pending queue is rebuilt from this on startup. The commit
    /// subscription only re-delivers blocks the worker *reprocesses*, and an
    /// already-processed block is a no-op — so a proof that was pending (enqueued
    /// but not yet submitted, e.g. a Moho proof deferred on a missing
    /// prerequisite) at restart time would otherwise be lost, permanently
    /// stalling the recursive Moho chain behind the gap.
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
    pub(crate) async fn proofs_to_backfill<C: ProverContext>(
        &self,
        ctx: &C,
    ) -> ProverResult<Vec<L1BlockCommitment>> {
        let genesis_height = self.genesis.height();

        // Highest persisted anchor. May belong to an abandoned reorg branch, so
        // it only bounds the walk — canonicality is established per height below.
        let Some(latest) = ctx.get_latest_anchor_state()? else {
            return Ok(Vec::new());
        };
        let latest_height = latest.chain_view.pow_state.last_verified_block.height();

        // Clamp to the canonical tip: after a reorg to a shorter chain the
        // highest persisted block can outrank the current L1 tip, and
        // `get_l1_block_hash` would fail for a height bitcoind no longer has.
        let tip_height = ctx.get_l1_block_count().await?;
        let mut height = latest_height.min(u32::try_from(tip_height).unwrap_or(u32::MAX));

        let mut backfill = Vec::new();
        while height > genesis_height {
            let block_id = ctx.get_l1_block_hash(u64::from(height)).await?;
            let commitment = L1BlockCommitment::new(height, block_id);

            // Heights above the processed tip are not yet persisted; the worker
            // re-processes and re-enqueues them on sync, so recovery skips them.
            if ctx.contains_anchor_state(&commitment)? {
                if ctx
                    .get_moho_proof(commitment)
                    .await
                    .map_err(|e| ProverError::storage("failed to fetch moho proof", e))?
                    .is_some()
                {
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

    /// Checks whether the prerequisites for a Moho recursive proof at `block`
    /// are available, returning them if so.
    pub async fn check_moho_prerequisite<C: ProverContext>(
        &self,
        ctx: &C,
        block: L1BlockCommitment,
    ) -> ProverResult<MohoPrerequisite> {
        // 1. ASM step proof is required.
        let asm_proof = ctx
            .get_asm_proof(L1Range::single(block))
            .await
            .map_err(|e| ProverError::storage("failed to fetch ASM step proof", e))?
            .ok_or(ProverError::NotFound(
                "ASM step proof not available yet for this block",
            ))?;

        let asm_receipt = asm_proof.0.receipt();
        let asm_attestation = StepMohoAttestation::from_ssz_bytes(
            asm_receipt.public_values().as_bytes(),
        )
        .map_err(|source| ProverError::Decode {
            what: "ASM attestation",
            source,
        })?;
        let asm_step_proof =
            StepMohoProof::new(asm_attestation, asm_receipt.proof().as_bytes().to_vec());

        // 2. Previous moho proof: required unless this is the genesis block.
        let parent = self.get_parent_commitment(ctx, block).await?;
        let prev_moho_proof = if parent == self.genesis {
            None
        } else {
            let proof = ctx
                .get_moho_proof(parent)
                .await
                .map_err(|e| ProverError::storage("failed to fetch previous moho proof", e))?
                .ok_or(ProverError::NotFound(
                    "previous moho recursive proof not available yet",
                ))?;
            let receipt = proof.0.receipt();
            let output = MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
                .map_err(|source| ProverError::Decode {
                    what: "moho recursive output",
                    source,
                })?;
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
    pub async fn build_asm_runtime_input<C: ProverContext>(
        &self,
        ctx: &C,
        range: &L1Range,
    ) -> ProverResult<RuntimeInput> {
        let commitment = range.start();

        // 1. Fetch the Bitcoin block.
        let block = ctx.get_l1_block(commitment.blkid()).await?;

        // 2. Fetch the auxiliary data stored during STF execution.
        let aux_data = ctx.get_aux_data(&commitment)?;

        let coinbase_inclusion_proof = match block.witness_root() {
            Some(_) => Some(TxidInclusionProof::generate(&block.txdata, 0)),
            None => None,
        };

        // 3. Build the step input.
        let step_input = AsmStepInput::new(block.clone(), aux_data, coinbase_inclusion_proof);

        // 4. Fetch the pre-state (anchor state for the parent block).
        let parent_commitment = self.get_parent_commitment(ctx, commitment).await?;

        let anchor_state = ctx.get_anchor_state(&parent_commitment)?;

        // 5. Compute the Moho pre-state from the anchor state.
        let moho_pre_state = self.get_moho_state(ctx, parent_commitment).await?;

        // 6. Build RuntimeInput.
        let runtime_input = RuntimeInput::new(
            moho_pre_state,
            anchor_state.as_ssz_bytes(),
            step_input.as_ssz_bytes(),
        );

        Ok(runtime_input)
    }

    /// Builds the [`MohoRecursiveInput`] for a Moho recursive proof at `l1_ref`.
    pub async fn build_moho_runtime_input<C: ProverContext>(
        &self,
        ctx: &C,
        prerequisite: MohoPrerequisite,
        l1_ref: L1BlockCommitment,
    ) -> ProverResult<MohoRecursiveInput> {
        let moho_predicate = self.moho_predicate.clone();

        let MohoPrerequisite {
            prev_moho_proof,
            incremental_step_proof,
        } = prerequisite;

        // The inner step proof is the ASM STF proof, so the step predicate is
        // the ASM predicate.
        let step_predicate = self.asm_predicate.clone();

        let parent = self.get_parent_commitment(ctx, l1_ref).await?;
        let parent_state = self.get_moho_state(ctx, parent).await?;

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
