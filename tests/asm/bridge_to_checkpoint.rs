//! Bridge -> Checkpoint subprotocol interaction tests
//!
//! Tests the propagation of deposit events from the bridge subprotocol
//! to the checkpoint subprotocol's available deposit tracking.
//!
//! Key interactions tested:
//! - Bridge deposit processing -> checkpoint `available_deposit_sum` increment
//! - Multiple deposits accumulate correctly
//! - Deposit amount matches bridge denomination

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    bridge::{create_test_bridge_setup, BridgeExt},
    test_harness::AsmTestHarnessBuilder,
};
use integration_tests::harness;

/// Verifies that a single bridge deposit updates the checkpoint's available deposit sum.
///
/// Flow:
/// 1. Configure bridge with known operators and denomination
/// 2. Submit a deposit transaction
/// 3. Mine a block so `process_msgs` delivers `DepositProcessed` to checkpoint
/// 4. Verify checkpoint's `available_deposit_sum` equals the deposit denomination
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_updates_checkpoint_available_sum() {
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    // Initialize subprotocols (genesis block creates initial state)
    harness.mine_block(None).await.unwrap();

    // Verify initial state: no deposits tracked yet
    let initial_checkpoint = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        initial_checkpoint.available_deposit_sum(),
        0,
        "Checkpoint should start with zero available deposits"
    );

    let initial_bridge = harness.bridge_state().unwrap();
    assert_eq!(
        initial_bridge.deposits().len(),
        0,
        "Bridge should start with no deposits"
    );

    // Submit a deposit
    harness.submit_deposit(&ctx, 0).await.unwrap();

    // The deposit is processed by bridge in `process_txs`, which emits DepositProcessed.
    // The checkpoint receives DepositProcessed in `process_msgs` of the same block.
    // However, since bridge processes AFTER checkpoint in `process_txs`, the message
    // is delivered in the same block's `process_msgs` phase.
    // Mine one more block to ensure the message has been delivered.
    harness.mine_block(None).await.unwrap();

    // Verify bridge state: deposit should be recorded
    let bridge_state = harness.bridge_state().unwrap();
    assert!(
        bridge_state.deposits().get_deposit(0).is_some(),
        "Bridge should have the deposit"
    );

    // Verify checkpoint state: available_deposit_sum should equal denomination
    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination.to_sat(),
        "Checkpoint available_deposit_sum should equal deposit denomination"
    );
}

/// Verifies that multiple deposits accumulate in the checkpoint's available sum.
///
/// Submits 3 deposits and verifies the sum equals 3 * denomination.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_deposits_accumulate_in_checkpoint() {
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    // Initialize subprotocols
    harness.mine_block(None).await.unwrap();

    let num_deposits = 3u32;
    for i in 0..num_deposits {
        harness.submit_deposit(&ctx, i).await.unwrap();
    }

    // Mine an extra block to ensure all messages are delivered
    harness.mine_block(None).await.unwrap();

    // Verify bridge state
    let bridge_state = harness.bridge_state().unwrap();
    assert_eq!(
        bridge_state.deposits().len(),
        num_deposits,
        "Bridge should have all deposits"
    );

    // Verify checkpoint accumulated sum
    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    let expected_sum = denomination.to_sat() * num_deposits as u64;
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        expected_sum,
        "Checkpoint available_deposit_sum should equal sum of all deposits"
    );
}
