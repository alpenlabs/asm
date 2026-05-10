//! Checkpoint subprotocol integration tests
//!
//! Tests checkpoint validation, withdrawal-intent processing, and the
//! resulting effects on the bridge's deposits and assignments tables.
//! Checkpoints flow through the same SPS-50 envelope transaction in every
//! case, so successful and rejection paths live alongside each other here.
//!
//! For admin→checkpoint interaction tests, see `admin_to_checkpoint.rs`.
//! For bridge→checkpoint deposit propagation, see `bridge_to_checkpoint.rs`.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    bridge::{create_test_bridge_setup, create_test_checkpoint_setup, BridgeExt},
    test_harness::AsmTestHarnessBuilder,
};
use integration_tests::harness;
use strata_asm_proto_bridge_v1_types::OperatorSelection;

/// Verifies that a checkpoint with withdrawal intents deducts from `available_deposit_sum`.
///
/// Flow:
/// 1. Submit 3 deposits → `available_deposit_sum` = 3 * denomination
/// 2. Submit a valid checkpoint with 1 withdrawal for `denomination` sats
/// 3. Verify `available_deposit_sum` == 2 * denomination (deducted)
/// 4. Verify `verified_tip.epoch` advanced to 1
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_deducts_from_deposit_sum() {
    let genesis_l1_height = AsmTestHarnessBuilder::DEFAULT_GENESIS_HEIGHT as u32;
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let (checkpoint_params, mut checkpoint_harness) =
        create_test_checkpoint_setup(genesis_l1_height);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_checkpoint_config(checkpoint_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    // Initialize subprotocols (genesis block)
    harness.mine_block(None).await.unwrap();

    // Submit 3 deposits
    let num_deposits = 3u32;
    for i in 0..num_deposits {
        harness.submit_deposit(&ctx, i).await.unwrap();
    }

    // Mine extra block for message delivery
    harness.mine_block(None).await.unwrap();

    // Verify deposits accumulated
    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    let expected_initial_sum = denomination.to_sat() * num_deposits as u64;
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        expected_initial_sum,
        "available_deposit_sum should equal 3 * denomination before withdrawal"
    );

    // Submit a checkpoint with 1 withdrawal for denomination sats
    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination.to_sat()])
        .await
        .unwrap();

    // Verify: available_deposit_sum deducted by withdrawal amount
    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    let expected_after = denomination.to_sat() * (num_deposits as u64 - 1);
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        expected_after,
        "available_deposit_sum should be deducted by withdrawal amount"
    );

    // Verify: checkpoint epoch advanced
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        1,
        "verified_tip epoch should advance to 1 after accepted checkpoint"
    );
}

/// Verifies that a single withdrawal intent for a multiple of the denomination is honored
/// and consumes that many UTXOs from the deposit pool.
///
/// Flow:
/// 1. Submit 3 deposits → `available_deposit_sum` = 3 * denomination
/// 2. Submit a checkpoint with 1 withdrawal for 2 * denomination sats
/// 3. Verify `available_deposit_sum` == 1 * denomination (2 UTXOs consumed by the one intent)
/// 4. Verify `verified_tip.epoch` advanced to 1
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_denomination_withdrawal_consumes_multiple_utxos() {
    let genesis_l1_height = AsmTestHarnessBuilder::DEFAULT_GENESIS_HEIGHT as u32;
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let (checkpoint_params, mut checkpoint_harness) =
        create_test_checkpoint_setup(genesis_l1_height);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_checkpoint_config(checkpoint_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    harness.mine_block(None).await.unwrap();

    let num_deposits = 3u32;
    for i in 0..num_deposits {
        harness.submit_deposit(&ctx, i).await.unwrap();
    }
    harness.mine_block(None).await.unwrap();

    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination.to_sat() * num_deposits as u64,
        "available_deposit_sum should equal 3 * denomination before withdrawal"
    );

    // Single intent for 2 * denomination: should consume 2 UTXOs.
    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination.to_sat() * 2])
        .await
        .unwrap();

    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination.to_sat(),
        "one 2x intent should consume two UTXOs, leaving one denomination available"
    );
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        1,
        "verified_tip epoch should advance to 1 after accepted multi-denomination checkpoint"
    );
}

/// Verifies that an accepted withdrawal moves the consumed deposit UTXO from the
/// bridge's deposits table into its assignments table, and that a pinned operator
/// selection is honored (the assignment goes to that operator).
///
/// Flow:
/// 1. Submit 2 deposits (indices 0, 1).
/// 2. Submit a checkpoint with one withdrawal for `denomination` sats, pinning operator 1.
/// 3. Verify deposit 0 (the oldest) is removed and deposit 1 remains.
/// 4. Verify a single assignment exists referencing deposit 0 and assigned to operator 1.
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_assigns_to_specific_operator() {
    let genesis_l1_height = AsmTestHarnessBuilder::DEFAULT_GENESIS_HEIGHT as u32;
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let (checkpoint_params, mut checkpoint_harness) =
        create_test_checkpoint_setup(genesis_l1_height);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_checkpoint_config(checkpoint_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    harness.mine_block(None).await.unwrap();

    for i in 0..2u32 {
        harness.submit_deposit(&ctx, i).await.unwrap();
    }
    harness.mine_block(None).await.unwrap();

    // Pin the withdrawal to operator index 1.
    let pinned_operator = 1u32;
    harness
        .submit_checkpoint_with_withdrawal_intents(
            &mut checkpoint_harness,
            &[(
                denomination.to_sat(),
                OperatorSelection::specific(pinned_operator),
            )],
        )
        .await
        .unwrap();

    let bridge_state = harness.bridge_state().unwrap();

    // Deposit 0 (oldest) consumed; deposit 1 still present.
    assert_eq!(
        bridge_state.deposits().len(),
        1,
        "exactly one deposit should remain after one withdrawal"
    );
    assert!(
        bridge_state.deposits().get_deposit(0).is_none(),
        "deposit 0 should have been removed"
    );
    assert!(
        bridge_state.deposits().get_deposit(1).is_some(),
        "deposit 1 should still be in the deposits table"
    );

    // Exactly one assignment, referencing deposit 0, pinned to operator 1.
    assert_eq!(bridge_state.assignments().len(), 1);
    let assignment = bridge_state
        .assignments()
        .get_assignment(0)
        .expect("assignment for deposit 0 should exist");
    assert_eq!(assignment.deposit_idx(), 0);
    assert_eq!(
        assignment.current_assignee(),
        pinned_operator,
        "pinned operator selection should be honored"
    );
}

/// Verifies that with no operator selection, the assignment falls back to a random
/// operator drawn from the deposit's notary set.
///
/// Flow:
/// 1. Submit 1 deposit.
/// 2. Submit a checkpoint with one withdrawal using `OperatorSelection::any()`.
/// 3. Verify the deposit was removed from the deposits table.
/// 4. Verify a single assignment exists with `current_assignee` within the notary set.
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_random_assignment_when_any_operator_selected() {
    let genesis_l1_height = AsmTestHarnessBuilder::DEFAULT_GENESIS_HEIGHT as u32;
    let num_operators = 3;
    let (bridge_params, ctx) = create_test_bridge_setup(num_operators);
    let (checkpoint_params, mut checkpoint_harness) =
        create_test_checkpoint_setup(genesis_l1_height);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_checkpoint_config(checkpoint_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    harness.mine_block(None).await.unwrap();

    harness.submit_deposit(&ctx, 0).await.unwrap();
    harness.mine_block(None).await.unwrap();

    harness
        .submit_checkpoint_with_withdrawal_intents(
            &mut checkpoint_harness,
            &[(denomination.to_sat(), OperatorSelection::any())],
        )
        .await
        .unwrap();

    let bridge_state = harness.bridge_state().unwrap();

    // Deposit consumed.
    assert!(
        bridge_state.deposits().is_empty(),
        "the only deposit should have been consumed by the withdrawal"
    );

    // Exactly one assignment, drawn from the notary set.
    assert_eq!(bridge_state.assignments().len(), 1);
    let assignment = bridge_state
        .assignments()
        .get_assignment(0)
        .expect("assignment for deposit 0 should exist");
    assert_eq!(assignment.deposit_idx(), 0);
    assert!(
        (assignment.current_assignee() as usize) < num_operators,
        "random assignee {} should be within notary range 0..{num_operators}",
        assignment.current_assignee(),
    );
}

/// Verifies that a checkpoint is rejected when an intent's amount is not a multiple of
/// the bridge denomination.
///
/// Flow:
/// 1. Submit 3 deposits → `available_deposit_sum` = 3 * denomination
/// 2. Submit a checkpoint with one withdrawal for `denomination + 1` sats
/// 3. Verify `available_deposit_sum` unchanged and `verified_tip.epoch` still 0
#[tokio::test(flavor = "multi_thread")]
async fn test_checkpoint_rejected_on_non_multiple_withdrawal() {
    let genesis_l1_height = AsmTestHarnessBuilder::DEFAULT_GENESIS_HEIGHT as u32;
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let (checkpoint_params, mut checkpoint_harness) =
        create_test_checkpoint_setup(genesis_l1_height);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_checkpoint_config(checkpoint_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    harness.mine_block(None).await.unwrap();

    let num_deposits = 3u32;
    for i in 0..num_deposits {
        harness.submit_deposit(&ctx, i).await.unwrap();
    }
    harness.mine_block(None).await.unwrap();

    let initial_sum = denomination.to_sat() * num_deposits as u64;

    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination.to_sat() + 1])
        .await
        .unwrap();

    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        initial_sum,
        "available_deposit_sum should be unchanged when the checkpoint is rejected"
    );
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        0,
        "verified_tip epoch should remain 0 when the checkpoint is rejected"
    );
}

/// Verifies that a checkpoint is rejected when withdrawal intents exceed available deposits.
///
/// Flow:
/// 1. Submit 1 deposit → `available_deposit_sum` = denomination
/// 2. Submit a checkpoint with withdrawals totaling > denomination
/// 3. Verify `available_deposit_sum` unchanged (still == denomination)
/// 4. Verify `verified_tip.epoch` still == 0 (checkpoint was rejected)
#[tokio::test(flavor = "multi_thread")]
async fn test_checkpoint_rejected_when_withdrawals_exceed_deposits() {
    let genesis_l1_height = AsmTestHarnessBuilder::DEFAULT_GENESIS_HEIGHT as u32;
    let (bridge_params, ctx) = create_test_bridge_setup(3);
    let (checkpoint_params, mut checkpoint_harness) =
        create_test_checkpoint_setup(genesis_l1_height);
    let denomination = ctx.denomination();

    let harness = AsmTestHarnessBuilder::default()
        .with_bridge_config(bridge_params)
        .with_checkpoint_config(checkpoint_params)
        .with_txindex()
        .build()
        .await
        .unwrap();

    // Initialize subprotocols (genesis block)
    harness.mine_block(None).await.unwrap();

    // Submit 1 deposit
    harness.submit_deposit(&ctx, 0).await.unwrap();

    // Mine extra block for message delivery
    harness.mine_block(None).await.unwrap();

    // Verify single deposit tracked
    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination.to_sat(),
        "available_deposit_sum should equal denomination after 1 deposit"
    );

    // Submit checkpoint with withdrawals exceeding available deposits (2 * denomination > 1 *
    // denomination). The checkpoint should be rejected, so submit_checkpoint_with_withdrawals
    // will still succeed (the tx is mined) but the ASM ignores the invalid checkpoint.
    harness
        .submit_checkpoint_with_withdrawals(
            &mut checkpoint_harness,
            &[denomination.to_sat(), denomination.to_sat()],
        )
        .await
        .unwrap();

    // Verify: available_deposit_sum unchanged
    let checkpoint_state = harness.checkpoint_new_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination.to_sat(),
        "available_deposit_sum should be unchanged when checkpoint is rejected"
    );

    // Verify: epoch did not advance
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        0,
        "verified_tip epoch should remain 0 when checkpoint is rejected"
    );
}
