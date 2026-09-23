//! Checking that a proof receipt is what it claims to be.
//!
//! Two questions have to be answered before a receipt can be trusted, and
//! neither one alone is enough:
//!
//! - Does the receipt satisfy the predicate its proofs are filed under? Checking it as a
//!   claim/witness pair against the [`PredicateKey`] is the same check the Moho guest runs on the
//!   proofs it recurses over, so a receipt accepted here is one the guest will accept — a Groth16
//!   verification under SP1, a Schnorr check over the public values natively.
//! - Is it the receipt for *this* transition? Verification alone only says "some valid run of this
//!   program", and the pre-state is an unconstrained input to both guests — a genuine run over a
//!   fabricated pre-state yields a valid receipt whose target is still the real block.
//!
//! The second question is answered by building the transition a receipt has to
//! attest to out of this node's own state — an [`ExpectedAttestation`] — and
//! comparing what the receipt commits against it whole. Checking field by
//! field would instead need an argument per field for why the ones left out
//! are already pinned, and those arguments live in the guest rather than here:
//! the ASM program derives both of a step's references from the same block
//! header, for instance, so matching the target already pins the origin.
//! Comparing the whole value needs no such argument, and cannot quietly stop
//! covering a field that Moho adds to an attestation later.
//!
//! A transition is a pair of [`StateRefAttestation`]s either way, each binding
//! a block's Moho [`StateReference`] — its block hash — to the
//! [`MohoStateCommitment`](moho_types::MohoStateCommitment) of the state at
//! it. An ASM step runs from the block's parent to the block. A Moho recursion
//! runs from genesis to the block, and
//! [`chain`](moho_types::RecursiveMohoAttestation::chain) carries that anchor
//! forward untouched for the life of the chain — which is why a recursion
//! built with no previous proof, anchored at its own parent, has to be caught
//! here: it is a truthful but far weaker claim than the one we file it under.
//!
//! Moho receipts carry one extra beyond the transition. The predicate key
//! their recursion verified under is compared on its own, because passing the
//! outer check says the receipt came from our Moho ELF and not what that run
//! recursed over.

use std::fmt;

use moho_recursive_proof::MohoRecursiveOutput;
use moho_types::{
    RecursiveMohoAttestation, StateRefAttestation, StateReference, StepMohoAttestation,
};
use ssz::Decode;
use strata_asm_prover_types::ProofId;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::{PredicateError, PredicateKey};
use thiserror::Error;
use zkaleido::ProofReceiptWithMetadata;

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
    input::parent_commitment,
};

/// Why a receipt is not an acceptable proof of the [`ProofId`] it is filed
/// under.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The receipt is not a valid witness for the predicate it is filed under.
    #[error("receipt does not satisfy its predicate: {0}")]
    Receipt(#[source] PredicateError),

    /// The receipt's public values could not be decoded, so there is no
    /// transition to compare the expected one against.
    #[error("failed to decode {what} from the receipt's public values: {source}")]
    Decode {
        /// The value that failed to decode.
        what: &'static str,
        /// The underlying SSZ decode error, preserved as the cause.
        #[source]
        source: ssz::DecodeError,
    },

    /// The receipt's transition ends somewhere ours does not: it proves a
    /// different block, or a run that did not land on the state this node
    /// derived for the block.
    #[error("receipt attests to target {0}")]
    WrongTarget(Box<EndpointMismatch>),

    /// The receipt's transition starts somewhere ours does not — the block's
    /// parent for an ASM step, the genesis anchor for a Moho recursion.
    #[error("receipt attests to origin {0}")]
    WrongOrigin(Box<EndpointMismatch>),

    /// The Moho receipt's recursion ran under a different predicate key than
    /// this backend proves with.
    #[error("moho receipt commits a predicate key this backend does not prove under")]
    PredicateMismatch,
}

/// One endpoint of a transition as this node derived it, against the one a
/// receipt actually committed.
///
/// Boxed where [`VerifyError`] carries it: a pair of attestations is 128 bytes
/// inline, which would widen every `Result` on the verify path for a case that
/// only arises when a receipt is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointMismatch {
    /// The endpoint this node derived.
    pub expected: StateRefAttestation,
    /// The endpoint the receipt actually commits to.
    pub actual: StateRefAttestation,
}

impl fmt::Display for EndpointMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, expected {}", self.actual, self.expected)
    }
}

/// The transition a receipt has to attest to, derived from this node's own
/// state.
///
/// One variant per proof kind, mirroring the two attestations Moho
/// distinguishes: an ASM step proof commits a [`StepMohoAttestation`] covering
/// one block, a Moho recursive proof a [`RecursiveMohoAttestation`] covering
/// the chain from genesis. Built by
/// [`ProofVerifier::expected_attestation`] and compared whole by
/// [`ProofVerifier::verify`], which also takes the proof kind from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedAttestation {
    /// An ASM step proof: from the block's parent into the block.
    Step(StepMohoAttestation),
    /// A Moho recursive proof: from genesis through to the block.
    Recursive(RecursiveMohoAttestation),
}

impl ExpectedAttestation {
    /// The `(origin, target)` endpoints both kinds are built out of: where the
    /// transition starts and where it ends.
    fn endpoints(&self) -> (&StateRefAttestation, &StateRefAttestation) {
        match self {
            Self::Step(step) => (step.from(), step.to()),
            Self::Recursive(recursive) => (recursive.genesis(), recursive.proven()),
        }
    }
}

impl fmt::Display for ExpectedAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Step(step) => step.fmt(f),
            Self::Recursive(recursive) => recursive.fmt(f),
        }
    }
}

/// Checks proof receipts against the predicate keys the worker proves under.
///
/// Two things have to hold. The receipt must satisfy its predicate, which is
/// the same claim/witness check the Moho guest runs on every proof it recurses
/// over, and it must attest to the transition this node derived for the block
/// itself.
///
/// Borrows the key pair the worker already holds rather than owning one, so it
/// is built for the duration of one orchestration step. No proving host is
/// needed: a predicate key carries everything the check requires, which is why
/// the guest can run the same one.
#[derive(Debug)]
pub struct ProofVerifier<'a> {
    asm: &'a PredicateKey,
    moho: &'a PredicateKey,
    genesis: L1BlockCommitment,
}

impl<'a> ProofVerifier<'a> {
    /// Creates a verifier over the `(asm, moho)` predicate key pair and the
    /// genesis block the recursive Moho chain is anchored at.
    pub fn new(asm: &'a PredicateKey, moho: &'a PredicateKey, genesis: L1BlockCommitment) -> Self {
        Self { asm, moho, genesis }
    }

    /// Builds the transition a receipt filed under `proof_id` has to attest
    /// to, out of the Moho states this node derived for itself.
    ///
    /// Kept apart from [`verify`](Self::verify) because the two failures mean
    /// different things: failing to read our own state says nothing about the
    /// source that served the receipt, while a receipt that does not match it
    /// says everything. Callers propagate the first and blame the source for
    /// the second.
    ///
    /// Every block involved has a stored Moho state. The queue is fed by the
    /// Moho commit stream, and the worker stores a block's state before it
    /// announces the commit, so a block that reaches verification is one whose
    /// state — and its parent's, committed earlier — is already on disk. The
    /// recursive arm also reads the genesis state, which the Moho worker
    /// ensures at construction, before this worker launches.
    pub async fn expected_attestation<C: ProverContext>(
        &self,
        ctx: &C,
        proof_id: &ProofId,
    ) -> ProverResult<ExpectedAttestation> {
        match proof_id {
            // The worker only ever proves single-block ranges, and a step runs
            // from the block's parent into the block.
            ProofId::Asm(range) => {
                let block = range.end();
                let parent = parent_commitment(ctx, block).await?;
                Ok(ExpectedAttestation::Step(StepMohoAttestation::new(
                    attested(ctx, parent).await?,
                    attested(ctx, block).await?,
                )))
            }
            ProofId::Moho(block) => Ok(ExpectedAttestation::Recursive(
                RecursiveMohoAttestation::new(
                    attested(ctx, self.genesis).await?,
                    attested(ctx, *block).await?,
                ),
            )),
        }
    }

    /// Verifies `receipt` and checks that it attests to exactly `expected`.
    ///
    /// `expected` also decides which predicate the receipt is checked against
    /// — a step attestation is what the ASM program commits, a recursive one
    /// what the Moho program commits — so a receipt can never be compared
    /// against a transition of the other kind.
    pub fn verify(
        &self,
        receipt: &ProofReceiptWithMetadata,
        expected: &ExpectedAttestation,
    ) -> Result<(), VerifyError> {
        let public_values = receipt.receipt().public_values().as_bytes();
        let proof = receipt.receipt().proof().as_bytes();

        let actual = match expected {
            ExpectedAttestation::Step(_) => {
                self.asm
                    .verify_claim_witness(public_values, proof)
                    .map_err(VerifyError::Receipt)?;

                ExpectedAttestation::Step(decode(public_values, "ASM step attestation")?)
            }
            ExpectedAttestation::Recursive(_) => {
                self.moho
                    .verify_claim_witness(public_values, proof)
                    .map_err(VerifyError::Receipt)?;

                let output: MohoRecursiveOutput = decode(public_values, "moho recursive output")?;
                if output.moho_predicate() != self.moho {
                    return Err(VerifyError::PredicateMismatch);
                }

                ExpectedAttestation::Recursive(output.attestation().clone())
            }
        };

        if &actual == expected {
            return Ok(());
        }
        Err(diverged(expected, &actual))
    }
}

/// The attestation this node derived for `block`: its Moho state reference
/// paired with the commitment of the state stored for it.
async fn attested<C: ProverContext>(
    ctx: &C,
    block: L1BlockCommitment,
) -> ProverResult<StateRefAttestation> {
    let state = ctx
        .get_moho_state(block)
        .await
        .map_err(|e| ProverError::storage("failed to fetch moho state", e))?
        .ok_or(ProverError::NotFound("moho state not found for block"))?;

    Ok(StateRefAttestation::new(
        state_reference(&block),
        state.compute_commitment(),
    ))
}

/// Decodes a receipt's public values, naming what was expected of them for the
/// error.
fn decode<T: Decode>(public_values: &[u8], what: &'static str) -> Result<T, VerifyError> {
    T::from_ssz_bytes(public_values).map_err(|source| VerifyError::Decode { what, source })
}

/// Reports which endpoint of a mismatched transition diverged.
///
/// Correctness rests on the whole-value comparison, not on this: it runs only
/// once that has already failed, and exists to say which half to look at. At
/// least one endpoint therefore differs, so agreeing targets leave the origins
/// as the only candidate.
fn diverged(expected: &ExpectedAttestation, actual: &ExpectedAttestation) -> VerifyError {
    let (expected_origin, expected_target) = expected.endpoints();
    let (actual_origin, actual_target) = actual.endpoints();

    if actual_target != expected_target {
        return VerifyError::WrongTarget(Box::new(EndpointMismatch {
            expected: *expected_target,
            actual: *actual_target,
        }));
    }
    VerifyError::WrongOrigin(Box::new(EndpointMismatch {
        expected: *expected_origin,
        actual: *actual_origin,
    }))
}

/// The Moho state reference for an L1 block, which is just its block hash.
fn state_reference(block: &L1BlockCommitment) -> StateReference {
    StateReference::new(*block.blkid().as_ref())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        BlockHash, CompactTarget, TxMerkleNode,
        block::{Header, Version},
        hashes::Hash,
    };
    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use moho_types::MohoStateCommitment;
    use ssz::Encode;
    use strata_btc_types::BlockHashExt;
    use strata_btc_verification::compute_block_hash;
    use strata_identifiers::{L1BlockId, RBuf32};
    use strata_predicate::PredicateTypeId;
    use zkaleido::{ProgramId, Proof, ProofMetadata, ProofReceipt, ProofType, PublicValues, ZkVm};

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32]).expect("valid signing key")
    }

    /// The predicate a native host built on `key` resolves to — see
    /// `backend::native::resolve_native_predicate`.
    fn predicate(key: &SigningKey) -> PredicateKey {
        PredicateKey::try_new(
            PredicateTypeId::Bip340Schnorr,
            key.verifying_key().to_bytes().to_vec(),
        )
        .expect("valid predicate key")
    }

    /// Builds a receipt the way `NativeHost` does when it proves: the proof is
    /// the host's Schnorr signature over the public values.
    fn receipt(signer: &SigningKey, public_values: Vec<u8>) -> ProofReceiptWithMetadata {
        let signature: Signature = signer.sign(&public_values);
        ProofReceiptWithMetadata::new(
            ProofReceipt::new(
                Proof::new(signature.to_bytes().to_vec()),
                PublicValues::new(public_values),
            ),
            ProofMetadata::new(
                ZkVm::Native,
                ProgramId([0u8; 32]),
                "test".to_owned(),
                ProofType::Core,
            ),
        )
    }

    fn block(seed: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(7, L1BlockId::from(RBuf32::from([seed; 32])))
    }

    /// Seed of the block the recursive chain is anchored at.
    const GENESIS: u8 = 0;
    /// Seed of the block proofs are filed for throughout, and of its parent.
    const PARENT: u8 = 2;
    const TARGET: u8 = 3;

    /// The Moho state commitment this node derived for a block. Distinct per
    /// block, so a receipt cannot pass by attesting to another block's state.
    fn our_state(seed: u8) -> MohoStateCommitment {
        MohoStateCommitment::new([seed ^ 0xF0; 32])
    }

    /// The endpoint this node derived for a block: our reference, our state.
    fn ours(seed: u8) -> StateRefAttestation {
        StateRefAttestation::new(state_reference(&block(seed)), our_state(seed))
    }

    /// What [`ProofVerifier::expected_attestation`] builds for an ASM step
    /// proof of `TARGET`: out of its parent, into the block.
    fn expected_step() -> ExpectedAttestation {
        ExpectedAttestation::Step(StepMohoAttestation::new(ours(PARENT), ours(TARGET)))
    }

    /// What it builds for a Moho recursive proof of `TARGET`: the chain from
    /// genesis.
    fn expected_recursive() -> ExpectedAttestation {
        ExpectedAttestation::Recursive(RecursiveMohoAttestation::new(ours(GENESIS), ours(TARGET)))
    }

    /// Public values an ASM step receipt commits.
    fn asm_public_values(from: StateRefAttestation, to: StateRefAttestation) -> Vec<u8> {
        StepMohoAttestation::new(from, to).as_ssz_bytes()
    }

    /// Public values a Moho recursive receipt commits: the attestation plus
    /// the predicate key the recursion ran under.
    fn moho_public_values(
        genesis: StateRefAttestation,
        proven: StateRefAttestation,
        recursed_under: &PredicateKey,
    ) -> Vec<u8> {
        MohoRecursiveOutput::new(
            RecursiveMohoAttestation::new(genesis, proven),
            recursed_under.clone(),
        )
        .as_ssz_bytes()
    }

    /// A verifier over two distinct predicates, so a receipt cannot pass the
    /// check for the wrong proof kind by accident.
    fn verifier<'a>(asm: &'a PredicateKey, moho: &'a PredicateKey) -> ProofVerifier<'a> {
        ProofVerifier::new(asm, moho, block(GENESIS))
    }

    /// The `(asm, moho)` predicates the worker proves under.
    fn predicates() -> (SigningKey, SigningKey, PredicateKey, PredicateKey) {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        (asm_key, moho_key, asm, moho)
    }

    #[test]
    fn asm_receipt_for_its_own_transition_verifies() {
        let (asm_key, _, asm, moho) = predicates();

        let receipt = receipt(&asm_key, asm_public_values(ours(PARENT), ours(TARGET)));

        verifier(&asm, &moho)
            .verify(&receipt, &expected_step())
            .expect("receipt should verify");
    }

    /// A valid proof of the wrong block is still the wrong proof.
    #[test]
    fn asm_receipt_for_another_block_is_rejected() {
        let (asm_key, _, asm, moho) = predicates();

        let receipt = receipt(&asm_key, asm_public_values(ours(TARGET), ours(TARGET + 1)));

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_step()),
            Err(VerifyError::WrongTarget(_))
        ));
    }

    /// A receipt produced under a different backend identity — the case the
    /// follower's fallback exists for.
    #[test]
    fn receipt_from_another_backend_is_rejected() {
        let (_, _, asm, moho) = predicates();

        let receipt = receipt(&key(9), asm_public_values(ours(PARENT), ours(TARGET)));

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_step()),
            Err(VerifyError::Receipt(_))
        ));
    }

    /// The expected transition picks the predicate, so an honest receipt of
    /// one kind cannot be passed off as the other.
    #[test]
    fn receipt_of_the_other_kind_is_rejected() {
        let (asm_key, _, asm, moho) = predicates();

        let receipt = receipt(&asm_key, asm_public_values(ours(PARENT), ours(TARGET)));

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_recursive()),
            Err(VerifyError::Receipt(_))
        ));
    }

    /// The pre-state is an unconstrained input to the guest, so a genuine run
    /// over a fabricated one still produces a receipt whose target block is
    /// the real one. The state it lands on is what gives it away.
    #[test]
    fn asm_receipt_over_a_forged_prestate_is_rejected() {
        let (asm_key, _, asm, moho) = predicates();

        let forged = asm_public_values(
            StateRefAttestation::new(
                state_reference(&block(PARENT)),
                MohoStateCommitment::new([0xAA; 32]),
            ),
            StateRefAttestation::new(
                state_reference(&block(TARGET)),
                MohoStateCommitment::new([0xBB; 32]),
            ),
        );
        let receipt = receipt(&asm_key, forged);

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_step()),
            Err(VerifyError::WrongTarget(_))
        ));
    }

    /// A step out of a block that is not ours does not extend our chain: the
    /// Moho recursion would refuse to chain it, so it is rejected before it
    /// can be stored and wedge every recursion at that height.
    #[test]
    fn asm_receipt_from_another_parent_is_rejected() {
        let (asm_key, _, asm, moho) = predicates();

        let receipt = receipt(&asm_key, asm_public_values(ours(GENESIS), ours(TARGET)));

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_step()),
            Err(VerifyError::WrongOrigin(_))
        ));
    }

    #[test]
    fn moho_receipt_for_its_own_chain_verifies() {
        let (_, moho_key, asm, moho) = predicates();

        let receipt = receipt(
            &moho_key,
            moho_public_values(ours(GENESIS), ours(TARGET), &moho),
        );

        verifier(&asm, &moho)
            .verify(&receipt, &expected_recursive())
            .expect("receipt should verify");
    }

    /// Our Moho ELF, but the run recursed under someone else's predicate.
    /// Passing the outer check says where the receipt came from, not what it
    /// verified, so the committed key needs its own comparison.
    #[test]
    fn moho_receipt_recursed_under_another_predicate_is_rejected() {
        let (_, moho_key, asm, moho) = predicates();

        let foreign = predicate(&key(9));
        let receipt = receipt(
            &moho_key,
            moho_public_values(ours(GENESIS), ours(TARGET), &foreign),
        );

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_recursive()),
            Err(VerifyError::PredicateMismatch)
        ));
    }

    /// A recursion built with no previous proof is anchored at its own parent.
    /// Its states are real, so the target check passes, but it proves one step
    /// rather than the chain we file it as — and `chain` carries that anchor
    /// forward untouched.
    #[test]
    fn moho_receipt_anchored_below_genesis_is_rejected() {
        let (_, moho_key, asm, moho) = predicates();

        let receipt = receipt(
            &moho_key,
            moho_public_values(ours(PARENT), ours(TARGET), &moho),
        );

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_recursive()),
            Err(VerifyError::WrongOrigin(_))
        ));
    }

    /// The right genesis block, but not the state we hold for it. Nothing
    /// downstream re-derives the anchor, so an unchecked commitment here would
    /// be carried by every later recursion for the life of the chain.
    #[test]
    fn moho_receipt_anchored_at_a_forged_genesis_state_is_rejected() {
        let (_, moho_key, asm, moho) = predicates();

        let forged_anchor = StateRefAttestation::new(
            state_reference(&block(GENESIS)),
            MohoStateCommitment::new([0xAA; 32]),
        );
        let receipt = receipt(
            &moho_key,
            moho_public_values(forged_anchor, ours(TARGET), &moho),
        );

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_recursive()),
            Err(VerifyError::WrongOrigin(_))
        ));
    }

    /// Public values that verify but carry no transition to compare.
    #[test]
    fn undecodable_public_values_are_rejected() {
        let (asm_key, _, asm, moho) = predicates();

        let receipt = receipt(&asm_key, b"not an attestation".to_vec());

        assert!(matches!(
            verifier(&asm, &moho).verify(&receipt, &expected_step()),
            Err(VerifyError::Decode { .. })
        ));
    }

    /// Both endpoints diverge when a receipt proves an unrelated transition.
    /// The target is the one reported: it says which block the receipt is
    /// actually for, which is what a reader needs first.
    #[test]
    fn a_wholly_different_transition_reports_its_target() {
        let (asm_key, _, asm, moho) = predicates();

        let receipt = receipt(&asm_key, asm_public_values(ours(8), ours(9)));

        let err = verifier(&asm, &moho)
            .verify(&receipt, &expected_step())
            .expect_err("unrelated transition should be rejected");

        let VerifyError::WrongTarget(mismatch) = err else {
            panic!("expected a target mismatch, got {err}");
        };
        assert_eq!(mismatch.expected, ours(TARGET));
        assert_eq!(mismatch.actual, ours(9));
    }

    fn header() -> Header {
        Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::from_byte_array([7u8; 32]),
            merkle_root: TxMerkleNode::from_byte_array([9u8; 32]),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            nonce: 42,
        }
    }

    /// The guest commits the state reference as `compute_block_hash(header)`,
    /// while the worker derives it from the block id in the [`ProofId`]. Both
    /// have to land on the same 32 bytes or every comparison would fail.
    #[test]
    fn state_reference_matches_the_hash_the_guest_commits() {
        let hash = compute_block_hash(&header());
        let block = L1BlockCommitment::new(7, hash.to_l1_block_id());

        assert_eq!(state_reference(&block).into_inner(), hash.to_byte_array());
    }
}
