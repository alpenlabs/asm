//! Authenticated spec activation across service restart and an activation-crossing reorg.
#![allow(
    unused_crate_dependencies,
    reason = "dependencies shared across integration tests"
)]

use bitcoin::{hashes::Hash, BlockHash};
use integration_tests::harness::{
    admin::{asm_stf_vk_update, AdminExt, DEFAULT_CONFIRMATION_DEPTH},
    spec::TestSuccessor,
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use strata_asm_common::AsmSpec;
use strata_asm_logs::{extract_next_predicate_from_logs, AsmStfUpdate};
use strata_asm_moho_worker::MohoStateStore;
use strata_asm_spec::StrataAsmSpec;
use strata_asm_worker::ExecutionRegistry;
use strata_predicate::PredicateKey;

fn execution_registry() -> ExecutionRegistry {
    let mut registry = ExecutionRegistry::default();
    registry
        .register(PredicateKey::always_accept(), StrataAsmSpec)
        .unwrap();
    // This harness tests native execution authority, not receipt verification.
    registry
        .register(PredicateKey::never_accept(), TestSuccessor)
        .unwrap();
    registry
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_activation_survives_restart_and_rolls_back_on_reorg() {
    let Setup {
        mut harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_execution_registry(execution_registry)
        .build()
        .await;
    harness.mine_block(None).await.unwrap();
    harness
        .submit_admin_action(
            &mut admin_ctx,
            asm_stf_vk_update(PredicateKey::never_accept()),
        )
        .await
        .unwrap();
    let (proposal, _) = harness.get_latest_asm_state().unwrap().unwrap();
    let activation_blocks = harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();
    let enacted = harness
        .find_log_in_blocks::<AsmStfUpdate>(&activation_blocks)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(enacted.new_predicate(), &PredicateKey::never_accept());
    let (activation, activation_state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(
        activation_state.spec_id,
        StrataAsmSpec::ID,
        "old spec executes the enacting block"
    );
    assert_eq!(
        harness
            .moho_context
            .get_moho_state(&activation)
            .unwrap()
            .next_predicate(),
        &PredicateKey::never_accept()
    );

    // Recovery must use the activation manifest, not the producing state's spec.
    harness.restart_workers().await.unwrap();
    assert_eq!(
        harness.get_latest_asm_state().unwrap().unwrap(),
        (activation, activation_state.clone())
    );
    harness.mine_block(None).await.unwrap();
    let (successor, successor_state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(successor_state.spec_id, TestSuccessor::ID);
    let successor_manifest = harness.get_manifest(&successor).unwrap();
    assert!(
        extract_next_predicate_from_logs(successor_manifest.logs()).is_none(),
        "ordinary-block restart must recover without an activation log"
    );

    // The ordinary successor block emits no activation log. Recovery must still
    // retain its program authority when all in-memory worker state is recreated.
    harness.restart_workers().await.unwrap();
    assert_eq!(
        harness.get_latest_asm_state().unwrap().unwrap(),
        (successor, successor_state.clone())
    );
    assert_eq!(
        harness.get_manifest(&successor).unwrap(),
        successor_manifest
    );
    harness.mine_block(None).await.unwrap();
    assert_eq!(
        harness.get_latest_asm_state().unwrap().unwrap().1.spec_id,
        TestSuccessor::ID
    );

    // Replace the proposal and all its descendants with empty blocks. The new
    // tip is higher, so both stores' latest pointers unambiguously select it.
    let proposal_hash = BlockHash::from_byte_array(*proposal.blkid().as_ref());
    harness.reorg(proposal_hash, 6).await.unwrap();
    let (replacement, replacement_state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(replacement_state.spec_id, StrataAsmSpec::ID);
    assert_eq!(
        harness
            .moho_context
            .get_moho_state(&replacement)
            .unwrap()
            .next_predicate(),
        &PredicateKey::always_accept()
    );
    // Fork data stays immutable and queryable after switching authority back.
    assert_eq!(
        harness.get_asm_state_at(&activation).unwrap(),
        activation_state
    );
    assert_eq!(
        harness.get_asm_state_at(&successor).unwrap(),
        successor_state
    );

    harness.restart_workers().await.unwrap();
    harness.mine_block(None).await.unwrap();
    assert_eq!(
        harness.get_latest_asm_state().unwrap().unwrap().1.spec_id,
        StrataAsmSpec::ID
    );
}
