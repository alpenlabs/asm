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
    bridge::BridgeExt,
    checkpoint::CheckpointExt,
    test_harness::{AsmTestHarnessBuilder, Setup},
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
    let Setup {
        harness,
        bridge: ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: nothing tracked yet.
    assert_eq!(
        harness.checkpoint_state().unwrap().available_deposit_sum(),
        0,
        "checkpoint should start with zero available deposits"
    );
    assert_eq!(
        harness.bridge_state().unwrap().deposits().len(),
        0,
        "bridge should start with no deposits"
    );

    // Act: one deposit (`submit_deposits` also mines the message-delivery block).
    harness.submit_deposits(&ctx, 1).await.unwrap();

    // Assert: bridge records the deposit and the checkpoint sees the denomination.
    assert!(
        harness
            .bridge_state()
            .unwrap()
            .deposits()
            .get_deposit(0)
            .is_some(),
        "bridge should have the deposit"
    );
    assert_eq!(
        harness.checkpoint_state().unwrap().available_deposit_sum(),
        denomination,
        "checkpoint available_deposit_sum should equal the deposit denomination"
    );
}

/// Verifies that multiple deposits accumulate in the checkpoint's available sum.
///
/// Submits 3 deposits and verifies the sum equals 3 * denomination.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_deposits_accumulate_in_checkpoint() {
    let Setup {
        harness,
        bridge: ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Act: 3 deposits.
    let num_deposits = 3u32;
    harness.submit_deposits(&ctx, num_deposits).await.unwrap();

    // Assert: bridge has all deposits; the checkpoint sum is the total.
    assert_eq!(
        harness.bridge_state().unwrap().deposits().len(),
        num_deposits,
        "bridge should have all deposits"
    );
    assert_eq!(
        harness.checkpoint_state().unwrap().available_deposit_sum(),
        denomination * num_deposits as u64,
        "checkpoint available_deposit_sum should equal the sum of all deposits"
    );
}
