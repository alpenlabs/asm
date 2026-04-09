//! Input preparation for proof generation.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type.

use std::sync::Arc;

use anyhow::{Context, Result};
use asm_storage::AsmStateDb;
use bitcoind_async_client::{Client, traits::Reader};
use moho_recursive_proof::{
    MohoRecursiveInput, MohoRecursiveOutput, MohoStateTransition, MohoTransitionWithProof,
};
use moho_runtime_impl::RuntimeInput;
use moho_runtime_interface::MohoProgram;
use moho_types::{MohoAttestation, MohoState};
use ssz::{Decode, Encode};
use strata_asm_proof_db::{ProofDb, SledProofDb};
use strata_asm_proof_impl::moho_program::{input::AsmStepInput, program::AsmStfProgram};
use strata_asm_proof_types::L1Range;
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_btc_verification::{self, TxidInclusionProof};
use strata_identifiers::L1BlockCommitment;
use strata_merkle::{BinaryMerkleTree, MerkleProofB32, Sha256NoPrefixHasher};
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher as TreeSha256Hasher, TreeHash};

/// Builds [`RuntimeInput`] for proof generation, dispatching by proof type.
pub(crate) struct InputBuilder {
    state_db: Arc<AsmStateDb>,
    bitcoin_client: Arc<Client>,
    proof_db: SledProofDb,
    genesis: L1BlockCommitment,
}

pub(crate) struct MohoPrerequisite {
    prev_moho_proof: Option<MohoTransitionWithProof>,
    incremental_step_proof: MohoTransitionWithProof,
}

impl InputBuilder {
    pub(crate) fn new(
        state_db: Arc<AsmStateDb>,
        bitcoin_client: Arc<Client>,
        proof_db: SledProofDb,
        genesis: L1BlockCommitment,
    ) -> Self {
        Self {
            state_db,
            bitcoin_client,
            proof_db,
            genesis,
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

    /// Get moho state after the execution of the given block
    async fn get_moho_state(&self, l1_ref: L1BlockCommitment) -> Result<MohoState> {
        let asm_state = self
            .state_db
            .get(&l1_ref)
            .context("failed to fetch anchor state")?
            .context("anchor state not found")?;
        let anchor_state = asm_state.state();

        // TODO: https://alpenlabs.atlassian.net/browse/STR-2958 Construct proper MohoState
        let inner_state_commitment = AsmStfProgram::compute_state_commitment(anchor_state);
        let moho_state = moho_types::MohoState::new(
            inner_state_commitment,
            strata_predicate::PredicateKey::always_accept(),
            moho_types::ExportState::new(vec![]),
        );
        Ok(moho_state)
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
            MohoAttestation::from_ssz_bytes(asm_receipt.public_values().as_bytes())
                .context("invalid ASM attestation in stored proof")?;
        let asm_transition = MohoStateTransition::new(
            asm_attestation.genesis().clone(),
            asm_attestation.proven().clone(),
        );
        let asm_step_proof =
            MohoTransitionWithProof::new(asm_transition, asm_receipt.proof().as_bytes().to_vec());

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
            Some(MohoTransitionWithProof::new(
                output.transition().clone(),
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
            .state_db
            .get_aux_data(&commitment)
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

        let asm_state = self
            .state_db
            .get(&parent_commitment)
            .context("failed to fetch parent anchor state")?
            .context("parent anchor state not found")?;
        let anchor_state = asm_state.state();

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
        let moho_predicate = PredicateKey::always_accept();

        let MohoPrerequisite {
            prev_moho_proof,
            incremental_step_proof,
        } = prerequisite;

        let step_predicate = PredicateKey::always_accept();

        let parent = self.get_parent_commitment(l1_ref).await?;
        let parent_state = self.get_moho_state(parent).await?;

        let leaves = vec![
            <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&parent_state.inner_state)
                .into_inner(),
            <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&parent_state.next_predicate)
                .into_inner(),
            <_ as TreeHash<TreeSha256Hasher>>::tree_hash_root(&parent_state.export_state)
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
