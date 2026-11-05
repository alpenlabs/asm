//! Auxiliary data verification tests.
//!
//! Aux data comes from the prover, not from L1, so the STF must check it against
//! the proven state before any subprotocol reads it.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use harness::test_harness::{AsmTestHarnessBuilder, Setup};
use integration_tests::harness;
use moho_runtime_impl::RuntimeInput;
use ssz::Encode;
use strata_asm_common::{AsmError, AuxData, AuxError, VerifiableManifestHash};
use strata_asm_manifest_types::AsmManifestHash;
use strata_asm_proof_impl::{
    moho_program::input::AsmStepInput, program::AsmStfProofProgram, test_utils::create_moho_state,
};
use strata_asm_spec::StrataAsmSpec;
use strata_asm_stf::compute_asm_transition;
use strata_asm_worker::ManifestMmrStore;
use strata_btc_verification::TxidInclusionProof;
use strata_predicate::PredicateKey;

/// A manifest hash whose MMR proof does not verify against the proven history
/// accumulator must fail the transition, and the proof program must panic on it.
///
/// Checkpoint verification reads manifest hashes from aux data. If a forged hash
/// got through, a prover could vouch for L1 history that never happened.
///
/// The genuine proof is checked first, so the forged case fails because of the
/// tampered hash and not because the proof was built wrong.
#[tokio::test(flavor = "multi_thread")]
async fn test_forged_manifest_hash_is_rejected() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;

    // Mine past genesis so the tip leaf is a real manifest, not a prefill sentinel.
    harness.mine_blocks(3).await.unwrap();
    let (_, pre_state) = harness
        .get_latest_asm_state()
        .unwrap()
        .expect("ASM state exists after mining");
    let accumulator = &pre_state.chain_view.history_accumulator;
    let index = accumulator.last_inserted_height();
    let genuine_hash = harness.get_manifest_hash(index).unwrap();
    let proof = harness
        .context
        .generate_mmr_proof_at(index, accumulator.num_entries())
        .unwrap();

    let block_hash = harness.mine_block(None).await.unwrap();
    let block = harness.get_block(block_hash).await.unwrap();
    let coinbase_proof = TxidInclusionProof::generate(&block.txdata, 0).expect("valid index");

    let genuine = AuxData::new(
        vec![VerifiableManifestHash::new(genuine_hash, proof.clone())],
        vec![],
    );
    compute_asm_transition(
        &StrataAsmSpec,
        &pre_state,
        &block,
        &genuine,
        Some(&coinbase_proof),
    )
    .expect("a genuine manifest proof verifies");

    let mut forged_bytes: [u8; 32] = *genuine_hash.as_ref();
    forged_bytes[0] ^= 1;
    let forged_hash = AsmManifestHash::from(forged_bytes);
    let forged = AuxData::new(
        vec![VerifiableManifestHash::new(forged_hash, proof)],
        vec![],
    );

    let err = compute_asm_transition(
        &StrataAsmSpec,
        &pre_state,
        &block,
        &forged,
        Some(&coinbase_proof),
    )
    .expect_err("a forged manifest hash must not verify");
    assert!(
        matches!(
            err,
            AsmError::InvalidAuxData(AuxError::InvalidMmrProof { index: i, hash })
                if i == index && hash == forged_hash
        ),
        "unexpected error: {err:?}"
    );

    let step_input = AsmStepInput::new(block, forged, Some(coinbase_proof));
    let runtime_input = RuntimeInput::new(
        create_moho_state(&pre_state, PredicateKey::always_accept()),
        pre_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            AsmStfProofProgram::execute(&runtime_input, StrataAsmSpec)
        }))
        .is_err(),
        "the proof program must not prove a transition with a forged manifest hash"
    );
}
