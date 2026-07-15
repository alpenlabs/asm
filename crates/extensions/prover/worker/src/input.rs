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
use strata_asm_prover_types::{L1Range, ProofId};
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

/// Leaf index of `next_predicate` in the [`MohoState`] commitment tree, whose
/// leaves are `inner_state`, `next_predicate`, `export_state`, and padding.
const NEXT_PREDICATE_LEAF_INDEX: usize = 1;

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

/// Result of assembling a Moho recursive proof input: either the input, ready
/// to prove, or the prerequisite proofs that are still missing.
///
/// Missing prerequisites are an expected scheduling state — the scheduler
/// defers the proof and enqueues what is missing — distinct from a
/// [`ProverError`], which signals an actual failure to read or decode data.
#[derive(Debug)]
pub enum MohoInput {
    /// All inputs were available. Boxed: the assembled input carries whole
    /// proofs and dwarfs the other variant.
    Ready(Box<MohoRecursiveInput>),
    /// Prerequisite proofs not yet available, listed for the scheduler to
    /// enqueue.
    MissingPrerequisites(Vec<ProofId>),
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

    /// Returns the latest worker-processed *canonical* block, used to seed the
    /// pending queue after a restart.
    ///
    /// Enqueuing this one block's proofs is enough to recover everything
    /// pending below it: the scheduler pulls a deferred proof's missing
    /// prerequisites back into the queue, recursively walking the chain down
    /// to the last block that already has a Moho proof.
    ///
    /// The seed must be canonical. Orphaned states from abandoned reorg
    /// branches are never pruned (see
    /// [`AnchorStateStore::get_latest_asm_state`](strata_asm_worker::AnchorStateStore::get_latest_asm_state)),
    /// so the highest persisted anchor can outrank the canonical chain; it
    /// only bounds the walk. From there, descend the canonical chain — clamped
    /// to the L1 tip, which can be lower after a reorg to a shorter chain — to
    /// the first height the worker actually processed.
    pub(crate) async fn recovery_seed<C: ProverContext>(
        &self,
        ctx: &C,
    ) -> ProverResult<Option<L1BlockCommitment>> {
        let Some(latest) = ctx.get_latest_anchor_state()? else {
            return Ok(None);
        };
        let latest_height = latest.chain_view.pow_state.last_verified_block.height();

        let tip_height = ctx.get_l1_block_count().await?;
        let mut height = latest_height.min(u32::try_from(tip_height).unwrap_or(u32::MAX));

        while height > self.genesis.height() {
            let block_id = ctx.get_l1_block_hash(u64::from(height)).await?;
            let commitment = L1BlockCommitment::new(height, block_id);
            if ctx.contains_anchor_state(&commitment)? {
                return Ok(Some(commitment));
            }
            height -= 1;
        }

        Ok(None)
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
        let step_input = AsmStepInput::new(block, aux_data, coinbase_inclusion_proof);

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

    /// Assembles the [`MohoRecursiveInput`] for a Moho recursive proof at
    /// `l1_ref`, or reports which prerequisite proofs are still missing: the
    /// ASM step proof for the block and, unless the parent is genesis, the
    /// Moho recursive proof for the parent. Only Moho proofs have proof
    /// prerequisites — ASM step proofs depend solely on worker-persisted
    /// state.
    ///
    /// Only one level of prerequisites is reported. The scheduler enqueues
    /// what is missing, and the recursion continues when those entries are
    /// themselves popped and checked — walking a gap of any depth back to the
    /// last proven block without re-probing the same ancestry from every
    /// dependent proof.
    pub async fn build_moho_runtime_input<C: ProverContext>(
        &self,
        ctx: &C,
        l1_ref: L1BlockCommitment,
    ) -> ProverResult<MohoInput> {
        // 1. Fetch the prerequisite proofs: the inner ASM step proof for this
        // block and, unless the parent is genesis, the previous Moho proof.
        let asm_proof = ctx
            .get_asm_proof(L1Range::single(l1_ref))
            .await
            .map_err(|e| ProverError::storage("failed to fetch ASM step proof", e))?;

        let parent = self.get_parent_commitment(ctx, l1_ref).await?;
        let requires_prev = parent != self.genesis;
        let prev_moho = if requires_prev {
            ctx.get_moho_proof(parent)
                .await
                .map_err(|e| ProverError::storage("failed to fetch previous moho proof", e))?
        } else {
            None
        };

        let (asm_proof, prev_moho) = match (asm_proof, requires_prev, prev_moho) {
            (Some(asm), false, _) => (asm, None),
            (Some(asm), true, Some(prev)) => (asm, Some(prev)),
            (asm, requires_prev, prev) => {
                let mut missing = Vec::new();
                if asm.is_none() {
                    missing.push(ProofId::Asm(L1Range::single(l1_ref)));
                }
                if requires_prev && prev.is_none() {
                    missing.push(ProofId::Moho(parent));
                }
                return Ok(MohoInput::MissingPrerequisites(missing));
            }
        };

        // 2. Decode the prerequisites into the proof types the input carries.
        let asm_receipt = asm_proof.0.receipt();
        let asm_attestation = StepMohoAttestation::from_ssz_bytes(
            asm_receipt.public_values().as_bytes(),
        )
        .map_err(|source| ProverError::Decode {
            what: "ASM attestation",
            source,
        })?;
        let incremental_step_proof =
            StepMohoProof::new(asm_attestation, asm_receipt.proof().as_bytes().to_vec());

        let prev_moho_proof = prev_moho
            .map(|proof| -> ProverResult<RecursiveMohoProof> {
                let receipt = proof.0.receipt();
                let output =
                    MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
                        .map_err(|source| ProverError::Decode {
                            what: "moho recursive output",
                            source,
                        })?;
                Ok(RecursiveMohoProof::new(
                    output.attestation().clone(),
                    receipt.proof().as_bytes().to_vec(),
                ))
            })
            .transpose()?;

        let moho_predicate = self.moho_predicate.clone();

        // The inner step proof is the ASM STF proof, so the step predicate is
        // the ASM predicate.
        let step_predicate = self.asm_predicate.clone();
        let parent_state = self.get_moho_state(ctx, parent).await?;

        let leaves = [
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
            .gen_proof(NEXT_PREDICATE_LEAF_INDEX)
            .expect("proof exists");
        let step_predicate_merkle_proof = MerkleProofB32::from_generic(&generic_proof);

        Ok(MohoInput::Ready(Box::new(MohoRecursiveInput::new(
            moho_predicate,
            prev_moho_proof,
            incremental_step_proof,
            step_predicate,
            step_predicate_merkle_proof,
        ))))
    }
}
