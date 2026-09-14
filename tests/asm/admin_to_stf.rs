//! Admin → ASM STF interaction tests
//!
//! Tests the propagation of ASM verifying key updates as `AsmStfUpdate` logs
//! in the manifest, which the `MohoProgram` uses to set the next predicate key.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{asm_stf_vk_update, AdminExt, DEFAULT_CONFIRMATION_DEPTH},
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use moho_runtime_impl::RuntimeInput;
use moho_types::ExportState;
use ssz::Encode;
use strata_asm_common::{prepare_state, AuxData};
use strata_asm_logs::AsmStfUpdate;
use strata_asm_proof_impl::{
    moho_program::{input::AsmStepInput, program::advance_export_state_with_logs},
    program::AsmStfProofProgram,
    test_utils::create_moho_state,
};
use strata_asm_spec::{StrataAsmSpecV1, StrataAsmTarget};
use strata_asm_stf::compute_asm_transition;
use strata_btc_verification::TxidInclusionProof;
use strata_predicate::{PredicateKey, PredicateTypeId};

/// Verifies ASM predicate updates emit an `AsmStfUpdate` log in the manifest after activation.
///
/// Flow:
/// 1. Submit ASM STF verifying-key update (gets queued)
/// 2. Mine blocks to trigger activation (confirmation_depth=2)
/// 3. Verify the manifest contains an `AsmStfUpdate` log with the correct predicate
#[tokio::test(flavor = "multi_thread")]
async fn test_asm_predicate_update_emits_log() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    // Submit an ASM predicate update (gets queued for StrataAdministrator role)
    let new_predicate = PredicateKey::always_accept();
    harness
        .submit_admin_action(&mut ctx, asm_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();

    // Verify it's queued, not applied yet
    let state = harness.admin_state().unwrap();
    assert_eq!(state.queued().len(), 1, "Predicate update should be queued");

    // Mine blocks to trigger activation.
    let activation_blocks = harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    // Admin queue should be empty
    let final_state = harness.admin_state().unwrap();
    assert_eq!(
        final_state.queued().len(),
        0,
        "Queue should be empty after activation"
    );

    // The update log is emitted at whichever block activated it; search the
    // blocks we just mined rather than dumping every stored manifest.
    let asm_stf_update = harness
        .find_log_in_blocks::<AsmStfUpdate>(&activation_blocks)
        .await
        .unwrap()
        .expect("expected an AsmStfUpdate log in the activation blocks");

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
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    // Submit an ASM predicate update (gets queued for StrataAdministrator role).
    let new_predicate = PredicateKey::never_accept();
    harness
        .submit_admin_action(&mut ctx, asm_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();

    // Verify it's queued.
    let state = harness.admin_state().unwrap();
    assert_eq!(state.queued().len(), 1, "Predicate update should be queued");

    // Mine first confirmation block.
    harness.mine_block(None).await.unwrap();

    // Capture the pre-state before the activation block.
    let (_, pre_anchor_state) = harness
        .get_latest_asm_state()
        .unwrap()
        .expect("ASM state must exist before activation block");

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
    let coinbase_inclusion_proof =
        TxidInclusionProof::generate(&activation_block.txdata, 0).expect("valid index");

    // Build AsmStepInput from the real activation block.
    let step_input = AsmStepInput::new(
        activation_block.clone(),
        AuxData::default(),
        Some(coinbase_inclusion_proof.clone()),
    );

    // Build MohoState pre-state with always_accept (the initial predicate) and an empty export
    // state — nothing has been exported before the activation block.
    let initial_predicate = PredicateKey::always_accept();
    let initial_export_state = ExportState::new(vec![]).unwrap();
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
    let prepared = prepare_state::<StrataAsmSpecV1>(&pre_anchor_state)
        .expect("pre-state prepares for the spec");
    let stf_output = compute_asm_transition(
        &prepared,
        &activation_block,
        step_input.aux_data(),
        Some(&coinbase_inclusion_proof),
    )
    .expect("compute_asm_transition failed");

    // The post MohoState should carry `never_accept` as the next predicate,
    // because the queued AsmStfUpdate log was emitted during the transition.
    let mut expected_post_moho = create_moho_state(&stf_output.state, new_predicate);

    // The proof program advances the export state by applying the transition's export logs to the
    // pre-state's export state. The bridge publishes its accumulated PoW as an
    // `ExportExtraDataUpdate` every block, so the expected post-state must apply the same logs to
    // match the proven commitment.
    expected_post_moho.export_state =
        advance_export_state_with_logs(initial_export_state, stf_output.manifest.logs());

    // The proven commitment in the attestation must match.
    assert_eq!(
        attestation.to().commitment(),
        &expected_post_moho.compute_commitment(),
        "post-state commitment should reflect the updated predicate (never_accept)"
    );
}

/// A successor release's verifying key, standing in for the artifact an upgrade
/// enacts.
fn successor_predicate() -> PredicateKey {
    PredicateKey::try_new(PredicateTypeId::Sp1Groth16, vec![0xa1; 32]).expect("valid predicate")
}

/// Verifies the worker rotates onto the enacted predicate and keeps executing
/// under it.
///
/// This is the half of the handover that only the real worker can show. The
/// pieces — deriving the predicate from the logs, persisting it, resolving it to
/// a specification — are each unit-tested, but whether the running worker
/// actually adopts what it derived, and does so before the next block, is a
/// property of the wiring. The next block is processed at all only if it does.
///
/// Flow:
/// 1. Bind the successor predicate in the worker's target table, as a release would
/// 2. Enact it through the admin subprotocol and mine to activation
/// 3. Assert the chain handed it over, then mine one more block under it
#[tokio::test(flavor = "multi_thread")]
async fn test_worker_rotates_onto_the_enacted_predicate() {
    let successor = successor_predicate();
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_target(successor.clone(), StrataAsmTarget::V1)
        .build()
        .await;

    harness
        .submit_admin_action(&mut ctx, asm_stf_vk_update(successor.clone()))
        .await
        .unwrap();
    harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    // The activation block handed over the successor predicate.
    let (_, moho_state) = harness
        .get_latest_moho_state()
        .unwrap()
        .expect("Moho state must exist after activation");
    assert_eq!(
        moho_state.next_predicate(),
        &successor,
        "the activation block must hand over the enacted predicate",
    );

    // Executing the next block requires resolving that predicate, so a
    // successful submit is the proof the worker adopted it.
    let height_before = harness.get_processed_height().unwrap();
    harness
        .mine_block(None)
        .await
        .expect("the worker must execute the block after the handover");
    assert_eq!(
        harness.get_processed_height().unwrap(),
        height_before + 1,
        "the block after the handover must be processed under the rotated predicate",
    );
}

/// Verifies the worker refuses the block after an upgrade it cannot execute,
/// rather than continuing under the rules it happens to have.
///
/// This is the failure the whole selection model exists to produce. A node whose
/// release does not implement the enacted rules must stop: continuing would build
/// state no proof can ever be made for, and on a node that does not prove nothing
/// else would notice.
///
/// The enacting block itself still succeeds — it ran under the old, bound
/// predicate. Only its successor is refused.
#[tokio::test(flavor = "multi_thread")]
async fn test_worker_halts_on_an_upgrade_it_cannot_execute() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    // Deliberately *not* bound in the target table: rules this build lacks.
    let unbound = successor_predicate();
    harness
        .submit_admin_action(&mut ctx, asm_stf_vk_update(unbound))
        .await
        .unwrap();

    // Activation lands on the last of these blocks, which still executes under
    // the genesis predicate.
    harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .expect("the enacting block runs under the predicate it was authorized by");

    let height_at_activation = harness.get_processed_height().unwrap();

    let result = harness.mine_block(None).await;

    assert!(
        result.is_err(),
        "the worker must refuse a block whose predicate it cannot resolve",
    );
    assert_eq!(
        harness.get_processed_height().unwrap(),
        height_at_activation,
        "a refused block must leave the committed anchor where it was",
    );
}
