//! Admin → Bridge subprotocol interaction tests
//!
//! Tests the propagation of operator set updates from the admin subprotocol
//! to the bridge subprotocol via interprotocol messaging.
//!
//! Key interactions tested:
//! - Operator additions → bridge operator table gains new members
//! - Operator removals → bridge operator table deactivates members
//! - Combined add/remove → both applied atomically after activation

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{create_test_admin_setup, operator_set_update, AdminContext, AdminExt},
    bridge::{create_test_bridge_setup, BridgeExt},
    test_harness::{AsmTestHarness, AsmTestHarnessBuilder},
};
use integration_tests::harness;
use strata_asm_proto_bridge_v1_txs::test_utils::create_test_operators;
use strata_crypto::EvenPublicKey;

const CONFIRMATION_DEPTH: u16 = 2;
const NUM_INITIAL_OPERATORS: usize = 3;

/// Sets up an ASM harness with admin + bridge subprotocols and mines the init block.
async fn setup() -> (AsmTestHarness, AdminContext) {
    let (admin_config, admin_ctx) = create_test_admin_setup(CONFIRMATION_DEPTH);
    let (bridge_config, _) = create_test_bridge_setup(NUM_INITIAL_OPERATORS);

    let harness = AsmTestHarnessBuilder::default()
        .with_admin_config(admin_config)
        .with_bridge_config(bridge_config)
        .build()
        .await
        .unwrap();

    // Initialize subprotocols
    harness.mine_block(None).await.unwrap();

    (harness, admin_ctx)
}

/// Submits an operator set update and mines enough blocks to activate it.
async fn submit_and_activate(
    harness: &AsmTestHarness,
    ctx: &mut AdminContext,
    add: Vec<EvenPublicKey>,
    remove: Vec<u32>,
) {
    harness
        .submit_admin_action(ctx, operator_set_update(add, remove))
        .await
        .unwrap();

    // Mine `CONFIRMATION_DEPTH` blocks to trigger activation
    for _ in 0..CONFIRMATION_DEPTH {
        harness.mine_block(None).await.unwrap();
    }
}

// ============================================================================
// Operator Set Updates → Bridge Operator Table
// ============================================================================

/// Verifies that adding an operator via admin propagates to the bridge after activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_add_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial_bridge = harness.bridge_state().unwrap();
    assert_eq!(initial_bridge.operators().len(), 3);

    let (_, new_pubkeys) = create_test_operators(1);
    submit_and_activate(&harness, &mut ctx, vec![new_pubkeys[0]], vec![]).await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(bridge.operators().len(), 4);
    assert!(bridge.operators().is_in_current_multisig(3));
}

/// Verifies that removing an operator via admin propagates to the bridge after activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_remove_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial_agg_key = *harness.bridge_state().unwrap().operators().agg_key();

    submit_and_activate(&harness, &mut ctx, vec![], vec![0]).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(!bridge.operators().is_in_current_multisig(0));
    assert!(bridge.operators().is_in_current_multisig(1));
    assert!(bridge.operators().is_in_current_multisig(2));
    assert_ne!(*bridge.operators().agg_key(), initial_agg_key);
}

/// Verifies combined add and remove in a single operator set update.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_add_and_remove_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial_agg_key = *harness.bridge_state().unwrap().operators().agg_key();

    let (_, new_pubkeys) = create_test_operators(1);
    submit_and_activate(&harness, &mut ctx, vec![new_pubkeys[0]], vec![1]).await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(bridge.operators().len(), 4);
    assert!(bridge.operators().is_in_current_multisig(0));
    assert!(!bridge.operators().is_in_current_multisig(1));
    assert!(bridge.operators().is_in_current_multisig(2));
    assert!(bridge.operators().is_in_current_multisig(3));
    assert_ne!(*bridge.operators().agg_key(), initial_agg_key);
}

/// Verifies the update is queued and does not affect the bridge until activated.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_update_does_not_apply_before_activation() {
    let (harness, mut ctx) = setup().await;

    let (_, new_pubkeys) = create_test_operators(1);

    // Submit but do NOT mine enough blocks to activate
    harness
        .submit_admin_action(&mut ctx, operator_set_update(vec![new_pubkeys[0]], vec![]))
        .await
        .unwrap();

    let admin_state = harness.admin_state().unwrap();
    assert_eq!(admin_state.queued().len(), 1, "Update should be queued");

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(
        bridge.operators().len(),
        3,
        "Bridge should be unchanged while update is queued"
    );
}
