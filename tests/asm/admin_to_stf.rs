//! Admin → ASM STF interaction tests
//!
//! Tests the propagation of ASM verifying key updates as `AsmStfUpdate` logs
//! in the manifest, which the `MohoProgram` uses to set the next predicate key.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{create_test_admin_setup, predicate_update, AdminExt},
    test_harness::AsmTestHarnessBuilder,
};
use integration_tests::harness;
use moho_runtime_impl::RuntimeInput;
use ssz::Encode;
use strata_asm_common::AuxData;
use strata_asm_logs::AsmStfUpdate;
use strata_asm_proof_impl::{
    moho_program::input::AsmStepInput, program::AsmStfProofProgram, test_utils::create_moho_state,
};
use strata_asm_spec::StrataAsmSpec;
use strata_asm_stf::compute_asm_transition;
use strata_asm_txs_admin::actions::updates::predicate::ProofType;
use strata_btc_verification::TxidInclusionProof;
use strata_predicate::PredicateKey;

/// Verifies ASM predicate updates emit an `AsmStfUpdate` log in the manifest after activation.
///
/// Flow:
/// 1. Submit predicate update with `ProofType::Asm` (gets queued)
/// 2. Mine blocks to trigger activation (confirmation_depth=2)
/// 3. Verify the manifest contains an `AsmStfUpdate` log with the correct predicate
#[tokio::test(flavor = "multi_thread")]
async fn test_asm_predicate_update_emits_log() {
    let (admin_config, mut ctx) = create_test_admin_setup(2);
    let harness = AsmTestHarnessBuilder::default()
        .with_admin_config(admin_config)
        .build()
        .await
        .unwrap();

    // Initialize subprotocols (genesis state has no sections)
    harness.mine_block(None).await.unwrap();

    // Submit an ASM predicate update (gets queued for StrataAdministrator role)
    let new_predicate = PredicateKey::always_accept();
    harness
        .submit_admin_action(
            &mut ctx,
            predicate_update(new_predicate.clone(), ProofType::Asm),
        )
        .await
        .unwrap();

    // Verify it's queued, not applied yet
    let state = harness.admin_state().unwrap();
    assert_eq!(state.queued().len(), 1, "Predicate update should be queued");

    // Mine blocks to trigger activation (confirmation_depth=2)
    harness.mine_block(None).await.unwrap();
    harness.mine_block(None).await.unwrap();

    // Admin queue should be empty
    let final_state = harness.admin_state().unwrap();
    assert_eq!(
        final_state.queued().len(),
        0,
        "Queue should be empty after activation"
    );

    // Find the AsmStfUpdate log in the stored manifests
    let manifests = harness.get_stored_manifests();
    let asm_stf_update = manifests
        .iter()
        .flat_map(|m| &m.logs)
        .find_map(|log| log.try_into_log::<AsmStfUpdate>().ok())
        .expect("expected an AsmStfUpdate log in manifests");

    assert_eq!(
        asm_stf_update.new_predicate(),
        &new_predicate,
        "AsmStfUpdate log should contain the new predicate"
    );
}

/// Verifies that `AsmStfProofProgram::execute()` produces a `MohoAttestation` whose post-state
/// commitment reflects the updated predicate key.
///
/// Uses the full test harness (bitcoind regtest) to naturally submit an admin predicate update,
/// mine blocks for activation, and then replays the activation block through
/// `AsmStfProofProgram::execute()` to verify the proof output.
///
/// Flow:
/// 1. Set up harness with `confirmation_depth=2`, submit predicate update (always_accept →
///    never_accept)
/// 2. Mine blocks to trigger activation, capturing the pre-state and activation block
/// 3. Build `RuntimeInput` from the captured state/block and run `AsmStfProofProgram::execute()`
/// 4. Verify the output attestation's post-state commitment reflects the new predicate
#[tokio::test(flavor = "multi_thread")]
async fn test_proof_program_reflects_predicate_update() {
    let (admin_config, mut ctx) = create_test_admin_setup(2);
    let harness = AsmTestHarnessBuilder::default()
        .with_admin_config(admin_config)
        .build()
        .await
        .unwrap();

    // Initialize subprotocols (genesis state has no sections yet).
    harness.mine_block(None).await.unwrap();

    // Submit an ASM predicate update (gets queued for StrataAdministrator role).
    let new_predicate = PredicateKey::never_accept();
    harness
        .submit_admin_action(
            &mut ctx,
            predicate_update(new_predicate.clone(), ProofType::Asm),
        )
        .await
        .unwrap();

    // Verify it's queued.
    let state = harness.admin_state().unwrap();
    assert_eq!(state.queued().len(), 1, "Predicate update should be queued");

    // Mine first confirmation block.
    harness.mine_block(None).await.unwrap();

    // Capture the pre-state before the activation block.
    let (_, pre_asm_state) = harness
        .get_latest_asm_state()
        .unwrap()
        .expect("ASM state must exist before activation block");
    let pre_anchor_state = pre_asm_state.state().clone();

    // Mine the activation block (confirmation_depth=2 reached).
    let activation_block_hash = harness.mine_block(None).await.unwrap();

    // Admin queue should be empty after activation.
    let final_state = harness.admin_state().unwrap();
    assert_eq!(
        final_state.queued().len(),
        0,
        "Queue should be empty after activation"
    );

    // Fetch the activation block.
    let activation_block = harness.get_block(activation_block_hash).await.unwrap();
    let coinbase_inclusion_proof = TxidInclusionProof::generate(&activation_block.txdata, 0);

    // Build AsmStepInput from the real activation block.
    let step_input = AsmStepInput::new(
        activation_block.clone(),
        AuxData::default(),
        Some(coinbase_inclusion_proof.clone()),
    );

    // Build MohoState pre-state with always_accept (the initial predicate).
    let initial_predicate = PredicateKey::always_accept();
    let moho_pre_state = create_moho_state(&pre_anchor_state, initial_predicate);

    // Construct RuntimeInput and execute the proof program.
    let runtime_input = RuntimeInput::new(
        moho_pre_state,
        pre_anchor_state.as_ssz_bytes(),
        step_input.as_ssz_bytes(),
    );
    let attestation =
        AsmStfProofProgram::execute(&runtime_input).expect("AsmStfProofProgram::execute failed");

    // Independently compute the expected post-state.
    let stf_output = compute_asm_transition(
        &StrataAsmSpec,
        &pre_anchor_state,
        &activation_block,
        step_input.aux_data(),
        Some(&coinbase_inclusion_proof),
    )
    .expect("compute_asm_transition failed");

    // The post MohoState should carry `never_accept` as the next predicate,
    // because the queued AsmStfUpdate log was emitted during the transition.
    let expected_post_moho = create_moho_state(&stf_output.state, new_predicate);

    // The proven commitment in the attestation must match.
    assert_eq!(
        attestation.to().commitment(),
        &expected_post_moho.compute_commitment(),
        "post-state commitment should reflect the updated predicate (never_accept)"
    );
}
