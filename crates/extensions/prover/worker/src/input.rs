//! Input preparation for proof generation.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type,
//! reading every dependency (proofs, Moho state, anchor state, aux data, L1
//! blocks) through the [`ProverContext`] rather than holding concrete handles.

use anyhow::{Context, Result};
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

use crate::ProverContext;

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
    ) -> Result<L1BlockCommitment> {
        let header = ctx
            .get_l1_block_header(l1_ref.blkid())
            .await
            .context("failed to fetch Bitcoin block header")?;
        let parent_hash = header.prev_blockhash;

        let parent_height = l1_ref
            .height()
            .checked_sub(1)
            .context("cannot generate ASM proof for height 0 — no parent block")?;

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
    ) -> Result<MohoState> {
        ctx.get_moho_state(l1_ref)
            .await
            .context("failed to fetch moho state")?
            .context("moho state not found for block")
    }

    /// Checks whether the prerequisites for a Moho recursive proof at `block`
    /// are available, returning them if so.
    pub async fn check_moho_prerequisite<C: ProverContext>(
        &self,
        ctx: &C,
        block: L1BlockCommitment,
    ) -> Result<MohoPrerequisite> {
        // 1. ASM step proof is required.
        let asm_proof = ctx
            .get_asm_proof(L1Range::single(block))
            .await
            .context("failed to fetch ASM step proof")?
            .context("ASM step proof not available yet for this block")?;

        let asm_receipt = asm_proof.0.receipt();
        let asm_attestation =
            StepMohoAttestation::from_ssz_bytes(asm_receipt.public_values().as_bytes())
                .map_err(|e| anyhow::anyhow!("invalid ASM attestation in stored proof: {e:?}"))?;
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
                .context("failed to fetch previous moho proof")?
                .context("previous moho recursive proof not available yet")?;
            let receipt = proof.0.receipt();
            let output = MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
                .map_err(|e| {
                    anyhow::anyhow!("invalid moho recursive output in stored proof: {e:?}")
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
    ) -> Result<RuntimeInput> {
        let commitment = range.start();

        // 1. Fetch the Bitcoin block.
        let block = ctx
            .get_l1_block(commitment.blkid())
            .await
            .context("failed to fetch Bitcoin block")?;

        // 2. Fetch the auxiliary data stored during STF execution.
        let aux_data = ctx
            .get_aux_data(&commitment)
            .context("failed to fetch aux data")?;

        let coinbase_inclusion_proof = match block.witness_root() {
            Some(_) => Some(TxidInclusionProof::generate(&block.txdata, 0)),
            None => None,
        };

        // 3. Build the step input.
        let step_input = AsmStepInput::new(block.clone(), aux_data, coinbase_inclusion_proof);

        // 4. Fetch the pre-state (anchor state for the parent block).
        let parent_commitment = self.get_parent_commitment(ctx, commitment).await?;

        let anchor_state = ctx
            .get_anchor_state(&parent_commitment)
            .context("failed to fetch parent anchor state")?;

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
    ) -> Result<MohoRecursiveInput> {
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
