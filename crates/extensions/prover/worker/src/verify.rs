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
//!   fabricated pre-state yields a valid receipt whose target is still the real block. So the
//!   public values are compared against the [`ProofId`] the receipt is filed under *and* against
//!   the Moho state this node derived for that block itself.
//!
//! Both proof kinds commit their block as a Moho [`StateReference`], which for
//! an L1 block is its block hash, and the state as a [`MohoStateCommitment`].
//! Matching the state commitment is what does the real work: a run that lands
//! on our state started from our state, short of a hash collision, so the
//! pre-state needs no separate check.
//!
//! Moho receipts carry two extras. The predicate key their recursion verified
//! under is compared on its own, because passing the outer check says the
//! receipt came from our Moho ELF and not what that run recursed over. And the
//! genesis the recursion is anchored at is compared against ours: a recursion
//! built with no previous proof is anchored at its own parent, which is a
//! truthful but far weaker claim than the one we file it under, and
//! [`chain`](moho_types::RecursiveMohoAttestation::chain) carries that anchor
//! forward untouched for the life of the chain.

use moho_recursive_proof::MohoRecursiveOutput;
use moho_types::{MohoStateCommitment, StateReference, StepMohoAttestation};
use ssz::Decode;
use strata_asm_prover_types::ProofId;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::{PredicateError, PredicateKey};
use thiserror::Error;
use zkaleido::ProofReceiptWithMetadata;

use crate::{
    ProverContext,
    errors::{ProverError, ProverResult},
};

/// Why a receipt is not an acceptable proof of the [`ProofId`] it is filed
/// under.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The receipt is not a valid witness for the predicate it is filed under.
    #[error("receipt does not satisfy its predicate: {0}")]
    Receipt(#[source] PredicateError),

    /// The receipt's public values could not be decoded, so there is nothing
    /// to bind the receipt to a block with.
    #[error("failed to decode {what} from the receipt's public values: {source}")]
    Decode {
        /// The value that failed to decode.
        what: &'static str,
        /// The underlying SSZ decode error, preserved as the cause.
        #[source]
        source: ssz::DecodeError,
    },

    /// The receipt proves a valid transition, but not the one it is filed
    /// under.
    #[error("receipt attests to state {actual}, expected {expected}")]
    WrongBlock {
        /// The reference the [`ProofId`] resolves to.
        expected: StateReference,
        /// The reference the receipt actually commits to.
        actual: StateReference,
    },

    /// The receipt proves a transition that did not land on the state this
    /// node derived for the block, so it ran over a different pre-state.
    #[error("receipt attests to moho state {actual}, expected {expected}")]
    WrongState {
        /// The commitment this node derived for the block itself.
        expected: MohoStateCommitment,
        /// The commitment the receipt actually attests to.
        actual: MohoStateCommitment,
    },

    /// The Moho receipt's recursion is anchored at some block other than the
    /// configured genesis, so it proves a shorter chain than it is filed for.
    #[error("moho receipt is anchored at {actual}, expected genesis {expected}")]
    WrongGenesis {
        /// The reference of the configured genesis block.
        expected: StateReference,
        /// The reference the recursion is actually anchored at.
        actual: StateReference,
    },

    /// The Moho receipt's recursion ran under a different predicate key than
    /// this backend proves with.
    #[error("moho receipt commits a predicate key this backend does not prove under")]
    PredicateMismatch,
}

/// Checks proof receipts against the predicate keys the worker proves under.
///
/// Two things have to hold. The receipt must satisfy its predicate, which is
/// the same claim/witness check the Moho guest runs on every proof it recurses
/// over, and its public values must name the block the [`ProofId`] is filed
/// under.
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

    /// Verifies `receipt` and binds it to `proof_id` and to `expected_state`,
    /// the Moho state commitment this node derived for the block itself.
    ///
    /// The caller reads `expected_state` from its own storage, so that a
    /// failure to look our own state up stays a different kind of problem from
    /// a receipt that does not hold up — only the latter says anything about
    /// the source that served it.
    pub fn verify(
        &self,
        proof_id: &ProofId,
        receipt: &ProofReceiptWithMetadata,
        expected_state: &MohoStateCommitment,
    ) -> Result<(), VerifyError> {
        let public_values = receipt.receipt().public_values().as_bytes();
        let proof = receipt.receipt().proof().as_bytes();

        match proof_id {
            ProofId::Asm(range) => {
                self.asm
                    .verify_claim_witness(public_values, proof)
                    .map_err(VerifyError::Receipt)?;

                let attestation =
                    StepMohoAttestation::from_ssz_bytes(public_values).map_err(|source| {
                        VerifyError::Decode {
                            what: "ASM step attestation",
                            source,
                        }
                    })?;
                // The worker only ever proves single-block ranges, and a step
                // attestation's target is that block.
                expect_block(attestation.to().reference(), &range.end())?;
                expect_state(attestation.to().commitment(), expected_state)
            }
            ProofId::Moho(block) => {
                self.moho
                    .verify_claim_witness(public_values, proof)
                    .map_err(VerifyError::Receipt)?;

                let output =
                    MohoRecursiveOutput::from_ssz_bytes(public_values).map_err(|source| {
                        VerifyError::Decode {
                            what: "moho recursive output",
                            source,
                        }
                    })?;
                expect_block(output.attestation().proven().reference(), block)?;
                expect_state(output.attestation().proven().commitment(), expected_state)?;

                // A recursion built with no previous proof is anchored at its
                // own parent. Its states are real, so the check above passes,
                // but it proves one step rather than the chain we file it as.
                let anchored_at = output.attestation().genesis().reference();
                let genesis = state_reference(&self.genesis);
                if anchored_at != &genesis {
                    return Err(VerifyError::WrongGenesis {
                        expected: genesis,
                        actual: *anchored_at,
                    });
                }

                if output.moho_predicate() != self.moho {
                    return Err(VerifyError::PredicateMismatch);
                }
                Ok(())
            }
        }
    }
}

/// Reads the Moho state commitment `proof_id`'s receipt has to attest to: the
/// one this node derived for the block itself, independently of any proof.
///
/// Always present for a proof the worker is handling. The queue is fed only by
/// the Moho commit stream, and the worker stores a block's Moho state before
/// it announces the commit, so every [`ProofId`] that reaches verification is
/// for a block whose state is already on disk.
pub(crate) async fn expected_state_commitment<C: ProverContext>(
    ctx: &C,
    proof_id: &ProofId,
) -> ProverResult<MohoStateCommitment> {
    let block = match proof_id {
        // Single-block ranges are the only kind the worker creates, and a step
        // attestation's target state is the one at that block.
        ProofId::Asm(range) => range.end(),
        ProofId::Moho(block) => *block,
    };

    let state = ctx
        .get_moho_state(block)
        .await
        .map_err(|e| ProverError::storage("failed to fetch moho state", e))?
        .ok_or(ProverError::NotFound("moho state not found for block"))?;

    Ok(state.compute_commitment())
}

/// Checks that a state commitment attested by a receipt is the one this node
/// derived for the same block.
fn expect_state(
    actual: &MohoStateCommitment,
    expected: &MohoStateCommitment,
) -> Result<(), VerifyError> {
    if actual != expected {
        return Err(VerifyError::WrongState {
            expected: *expected,
            actual: *actual,
        });
    }
    Ok(())
}

/// The Moho state reference for an L1 block, which is just its block hash.
fn state_reference(block: &L1BlockCommitment) -> StateReference {
    StateReference::new(*block.blkid().as_ref())
}

/// Checks that a reference committed by a receipt names `expected`.
fn expect_block(actual: &StateReference, expected: &L1BlockCommitment) -> Result<(), VerifyError> {
    let expected = state_reference(expected);
    if actual != &expected {
        return Err(VerifyError::WrongBlock {
            expected,
            actual: *actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        BlockHash, CompactTarget, TxMerkleNode,
        block::{Header, Version},
        hashes::Hash,
    };
    use k256::schnorr::{Signature, SigningKey, signature::Signer};
    use moho_types::{MohoStateCommitment, RecursiveMohoAttestation, StateRefAttestation};
    use ssz::Encode;
    use strata_asm_prover_types::L1Range;
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

    /// The Moho state commitment this node derived for a block. Distinct per
    /// block, so a receipt cannot pass by attesting to another block's state.
    fn our_state(seed: u8) -> MohoStateCommitment {
        MohoStateCommitment::new([seed ^ 0xF0; 32])
    }

    /// The attestation an honest run commits for a block: our reference and
    /// our state.
    fn attested(seed: u8) -> StateRefAttestation {
        StateRefAttestation::new(state_reference(&block(seed)), our_state(seed))
    }

    /// Public values an ASM step receipt commits: an attestation whose target
    /// is the proven block.
    fn asm_public_values(target: u8) -> Vec<u8> {
        StepMohoAttestation::new(attested(GENESIS), attested(target)).as_ssz_bytes()
    }

    /// Public values a Moho recursive receipt commits: the attestation plus the
    /// predicate key the recursion ran under.
    fn moho_public_values(anchor: u8, proven: u8, recursed_under: &PredicateKey) -> Vec<u8> {
        MohoRecursiveOutput::new(
            RecursiveMohoAttestation::new(attested(anchor), attested(proven)),
            recursed_under.clone(),
        )
        .as_ssz_bytes()
    }

    /// A verifier over two distinct predicates, so a receipt cannot pass the
    /// check for the wrong proof kind by accident.
    fn verifier<'a>(asm: &'a PredicateKey, moho: &'a PredicateKey) -> ProofVerifier<'a> {
        ProofVerifier::new(asm, moho, block(GENESIS))
    }

    #[test]
    fn asm_receipt_for_its_own_block_verifies() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        let target = 3;

        let receipt = receipt(&asm_key, asm_public_values(target));

        verifier(&asm, &moho)
            .verify(
                &ProofId::Asm(L1Range::single(block(target))),
                &receipt,
                &our_state(target),
            )
            .expect("receipt should verify");
    }

    /// A valid proof of the wrong block is still the wrong proof.
    #[test]
    fn asm_receipt_for_another_block_is_rejected() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));

        let receipt = receipt(&asm_key, asm_public_values(3));

        assert!(matches!(
            verifier(&asm, &moho).verify(
                &ProofId::Asm(L1Range::single(block(4))),
                &receipt,
                &our_state(4)
            ),
            Err(VerifyError::WrongBlock { .. })
        ));
    }

    /// A receipt produced under a different backend identity — the case the
    /// follower's fallback exists for.
    #[test]
    fn receipt_from_another_backend_is_rejected() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        let target = 3;

        let receipt = receipt(&key(9), asm_public_values(target));

        assert!(matches!(
            verifier(&asm, &moho).verify(
                &ProofId::Asm(L1Range::single(block(target))),
                &receipt,
                &our_state(target)
            ),
            Err(VerifyError::Receipt(_))
        ));
    }

    #[test]
    fn moho_receipt_for_its_own_block_verifies() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        let proven = 3;

        let receipt = receipt(&moho_key, moho_public_values(GENESIS, proven, &moho));

        verifier(&asm, &moho)
            .verify(&ProofId::Moho(block(proven)), &receipt, &our_state(proven))
            .expect("receipt should verify");
    }

    /// Our Moho ELF, but the run recursed under someone else's predicate.
    /// Passing the outer check says where the receipt came from, not what it
    /// verified, so the committed key needs its own comparison.
    #[test]
    fn moho_receipt_recursed_under_another_predicate_is_rejected() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        let proven = 3;

        let foreign = predicate(&key(9));
        let receipt = receipt(&moho_key, moho_public_values(GENESIS, proven, &foreign));

        assert!(matches!(
            verifier(&asm, &moho).verify(
                &ProofId::Moho(block(proven)),
                &receipt,
                &our_state(proven)
            ),
            Err(VerifyError::PredicateMismatch)
        ));
    }

    /// The pre-state is an unconstrained input to the guest, so a genuine run
    /// over a fabricated one still produces a receipt whose target is the real
    /// block. Only the state commitment separates it from the honest proof.
    #[test]
    fn asm_receipt_over_a_forged_prestate_is_rejected() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        let target = 3;

        let forged = StepMohoAttestation::new(
            StateRefAttestation::new(
                state_reference(&block(GENESIS)),
                MohoStateCommitment::new([0xAA; 32]),
            ),
            StateRefAttestation::new(
                state_reference(&block(target)),
                MohoStateCommitment::new([0xBB; 32]),
            ),
        );
        let receipt = receipt(&asm_key, forged.as_ssz_bytes());

        assert!(matches!(
            verifier(&asm, &moho).verify(
                &ProofId::Asm(L1Range::single(block(target))),
                &receipt,
                &our_state(target)
            ),
            Err(VerifyError::WrongState { .. })
        ));
    }

    /// A recursion built with no previous proof is anchored at its own parent.
    /// Every state in it is real, so the state check passes, but it proves one
    /// step rather than the chain from genesis it is filed as — and `chain`
    /// carries that anchor forward untouched.
    #[test]
    fn moho_receipt_anchored_below_genesis_is_rejected() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));
        let proven = 3;

        let truncated = moho_public_values(proven - 1, proven, &moho);
        let receipt = receipt(&moho_key, truncated);

        assert!(matches!(
            verifier(&asm, &moho).verify(
                &ProofId::Moho(block(proven)),
                &receipt,
                &our_state(proven)
            ),
            Err(VerifyError::WrongGenesis { .. })
        ));
    }

    /// Public values that verify but carry nothing we can read a block out of.
    #[test]
    fn undecodable_public_values_are_rejected() {
        let (asm_key, moho_key) = (key(1), key(2));
        let (asm, moho) = (predicate(&asm_key), predicate(&moho_key));

        let receipt = receipt(&asm_key, b"not an attestation".to_vec());

        assert!(matches!(
            verifier(&asm, &moho).verify(
                &ProofId::Asm(L1Range::single(block(3))),
                &receipt,
                &our_state(3)
            ),
            Err(VerifyError::Decode { .. })
        ));
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
    /// have to land on the same 32 bytes or every binding check would fail.
    #[test]
    fn state_reference_matches_the_hash_the_guest_commits() {
        let hash = compute_block_hash(&header());
        let block = L1BlockCommitment::new(7, hash.to_l1_block_id());

        assert_eq!(state_reference(&block).into_inner(), hash.to_byte_array());
    }

    #[test]
    fn expect_block_rejects_another_block() {
        let hash = compute_block_hash(&header());
        let block = L1BlockCommitment::new(7, hash.to_l1_block_id());
        let other = StateReference::new([1u8; 32]);

        assert!(expect_block(&state_reference(&block), &block).is_ok());
        assert!(matches!(
            expect_block(&other, &block),
            Err(VerifyError::WrongBlock { .. })
        ));
    }
}
