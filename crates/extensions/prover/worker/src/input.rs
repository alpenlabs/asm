//! Proof input preparation and validation of expected public outputs.
//!
//! Builds the [`RuntimeInput`] required by the ZkVM program for each proof type,
//! reading every dependency (proofs, Moho state, anchor state, aux data, L1
//! blocks) through the [`ProverContext`] rather than holding concrete handles.
//! Uses the same persisted chain state to resolve program authority and check outputs.

use moho_recursive_proof::{MohoRecursiveInput, MohoRecursiveOutput};
use moho_runtime_impl::RuntimeInput;
use moho_types::{
    MohoState, RecursiveMohoAttestation, RecursiveMohoProof, StateRefAttestation, StateReference,
    StepMohoAttestation, StepMohoProof,
};
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

/// Builds proof inputs and checks expected program authority and public outputs.
///
/// Holds only the values that are fixed for the lifetime of the prover (the
/// genesis commitment and the Moho predicate); all per-block data is read
/// from the [`ProverContext`] passed to each method.
#[derive(Debug)]
pub struct InputBuilder {
    genesis: L1BlockCommitment,
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
    pub fn new(genesis: L1BlockCommitment, moho_predicate: PredicateKey) -> Self {
        Self {
            genesis,
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

    /// The genesis block commitment the recursive Moho chain is rooted at.
    /// Proofs exist only for blocks strictly above it.
    pub(crate) fn genesis(&self) -> L1BlockCommitment {
        self.genesis
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
        // The current ASM input contains one block. Reject larger ranges
        // rather than proving only the first block of the requested range.
        // Future multi-block support must cover every requested block and handle
        // upgrade boundaries, where the authorized execution predicate changes:
        // split the range at those boundaries or compose proofs across programs.
        if range.start() != range.end() {
            return Err(ProverError::UnsupportedAsmRange);
        }
        let commitment = range.start();

        // 1. Fetch the Bitcoin block.
        let block = ctx.get_l1_block(commitment.blkid()).await?;

        // 2. Fetch the auxiliary data stored during STF execution.
        let aux_data = ctx.get_aux_data(&commitment)?;

        // `None` only for a block with no transactions. The guest rejects that when it re-runs
        // the STF, so there is nothing to check here.
        let coinbase_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);

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

        // Verify this step under its parent's authority, not the startup artifact.
        let parent_state = self.get_moho_state(ctx, parent).await?;
        let step_predicate = parent_state.next_predicate().clone();

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

    /// Resolves the required program from the ASM parent state or fixed Moho predicate.
    pub(crate) async fn expected_predicate<C: ProverContext>(
        &self,
        ctx: &C,
        id: ProofId,
    ) -> ProverResult<PredicateKey> {
        match id {
            ProofId::Asm(range) => {
                if range.start() != range.end() {
                    return Err(ProverError::UnsupportedAsmRange);
                }
                let parent = self.get_parent_commitment(ctx, range.start()).await?;
                Ok(self
                    .get_moho_state(ctx, parent)
                    .await?
                    .next_predicate()
                    .clone())
            }
            ProofId::Moho(_) => Ok(self.moho_predicate.clone()),
        }
    }

    /// Checks decoded public outputs against the requested transition and persisted states.
    pub(crate) async fn validate_output<C: ProverContext>(
        &self,
        ctx: &C,
        id: ProofId,
        bytes: &[u8],
    ) -> ProverResult<()> {
        let (from, to) = match id {
            ProofId::Asm(range) => (
                self.get_parent_commitment(ctx, range.start()).await?,
                range.end(),
            ),
            ProofId::Moho(block) => (self.genesis, block),
        };
        let from_state = self.get_moho_state(ctx, from).await?;
        let to_state = self.get_moho_state(ctx, to).await?;
        let from = StateRefAttestation::new(
            StateReference::new(*from.blkid().as_ref()),
            from_state.compute_commitment(),
        );
        let to = StateRefAttestation::new(
            StateReference::new(*to.blkid().as_ref()),
            to_state.compute_commitment(),
        );
        let matches = match id {
            ProofId::Asm(_) => StepMohoAttestation::from_ssz_bytes(bytes)
                .map(|actual| actual == StepMohoAttestation::new(from, to))
                .unwrap_or(false),
            ProofId::Moho(_) => MohoRecursiveOutput::from_ssz_bytes(bytes)
                .map(|actual| {
                    actual.attestation() == &RecursiveMohoAttestation::new(from, to)
                        && actual.moho_predicate() == &self.moho_predicate
                })
                .unwrap_or(false),
        };
        if !matches {
            return Err(ProverError::ReceiptMismatch);
        }
        Ok(())
    }
}
