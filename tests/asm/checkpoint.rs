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
    bridge::{BridgeExt, DEFAULT_NUM_OPERATORS},
    checkpoint::CheckpointExt,
    test_harness::{AsmTestHarnessBuilder, Setup},
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
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 3 deposits → available_deposit_sum == 3 * denomination.
    harness.submit_deposits(&ctx, 3).await.unwrap();
    assert_eq!(
        harness.checkpoint_state().unwrap().available_deposit_sum(),
        denomination * 3,
        "available_deposit_sum should equal 3 * denomination before withdrawal"
    );

    // Act: one withdrawal for `denomination` sats.
    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination])
        .await
        .unwrap();

    // Assert: deducted by one denomination and the epoch advanced.
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination * 2,
        "available_deposit_sum should be deducted by the withdrawal amount"
    );
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        1,
        "verified_tip epoch should advance to 1 after an accepted checkpoint"
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
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 3 deposits.
    harness.submit_deposits(&ctx, 3).await.unwrap();
    assert_eq!(
        harness.checkpoint_state().unwrap().available_deposit_sum(),
        denomination * 3,
        "available_deposit_sum should equal 3 * denomination before withdrawal"
    );

    // Act: a single intent for 2 * denomination should consume 2 UTXOs.
    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination * 2])
        .await
        .unwrap();

    // Assert.
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination,
        "one 2x intent should consume two UTXOs, leaving one denomination available"
    );
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        1,
        "verified_tip epoch should advance to 1 after an accepted multi-denomination checkpoint"
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
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 2 deposits (indices 0, 1).
    harness.submit_deposits(&ctx, 2).await.unwrap();

    // Act: one withdrawal for `denomination`, pinned to operator 1.
    let pinned_operator = 1u32;
    harness
        .submit_checkpoint_with_withdrawal_intents(
            &mut checkpoint_harness,
            &[(denomination, OperatorSelection::specific(pinned_operator))],
        )
        .await
        .unwrap();

    // Assert: deposit 0 consumed, deposit 1 remains, one assignment pinned to operator 1.
    let bridge_state = harness.bridge_state().unwrap();
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

    assert_eq!(
        bridge_state.assignments().len(),
        1,
        "exactly one assignment should exist"
    );
    let assignment = bridge_state
        .assignments()
        .get_assignment(0)
        .expect("assignment for deposit 0 should exist");
    assert_eq!(
        assignment.deposit_idx(),
        0,
        "assignment should reference deposit 0"
    );
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
    let num_operators = DEFAULT_NUM_OPERATORS;
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .num_operators(num_operators)
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 1 deposit.
    harness.submit_deposits(&ctx, 1).await.unwrap();

    // Act: one withdrawal with no operator pin (random assignment).
    harness
        .submit_checkpoint_with_withdrawal_intents(
            &mut checkpoint_harness,
            &[(denomination, OperatorSelection::any())],
        )
        .await
        .unwrap();

    // Assert: deposit consumed; one assignment drawn from the notary set.
    let bridge_state = harness.bridge_state().unwrap();
    assert!(
        bridge_state.deposits().is_empty(),
        "the only deposit should have been consumed by the withdrawal"
    );
    assert_eq!(
        bridge_state.assignments().len(),
        1,
        "exactly one assignment should exist"
    );
    let assignment = bridge_state
        .assignments()
        .get_assignment(0)
        .expect("assignment for deposit 0 should exist");
    assert_eq!(
        assignment.deposit_idx(),
        0,
        "assignment should reference deposit 0"
    );
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
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 3 deposits.
    harness.submit_deposits(&ctx, 3).await.unwrap();
    let initial_sum = denomination * 3;

    // Act: a withdrawal that is not a multiple of the denomination → rejected.
    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination + 1])
        .await
        .unwrap();

    // Assert: state unchanged.
    let checkpoint_state = harness.checkpoint_state().unwrap();
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
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 1 deposit.
    harness.submit_deposits(&ctx, 1).await.unwrap();
    assert_eq!(
        harness.checkpoint_state().unwrap().available_deposit_sum(),
        denomination,
        "available_deposit_sum should equal denomination after 1 deposit"
    );

    // Act: withdraw 2 * denomination (> available) → rejected. The tx is still mined, but the
    // ASM ignores the invalid checkpoint.
    harness
        .submit_checkpoint_with_withdrawals(&mut checkpoint_harness, &[denomination, denomination])
        .await
        .unwrap();

    // Assert: state unchanged.
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        checkpoint_state.available_deposit_sum(),
        denomination,
        "available_deposit_sum should be unchanged when the checkpoint is rejected"
    );
    assert_eq!(
        checkpoint_state.verified_tip().epoch,
        0,
        "verified_tip epoch should remain 0 when the checkpoint is rejected"
    );
}

/// Multiple `OperatorSelection::any()` withdrawal intents carried by a single checkpoint
/// distribute across operators rather than all funneling onto one.
///
/// Flow:
/// 1. Submit 10 deposits (indices 0..=9) with a 10-operator notary set.
/// 2. Submit a single checkpoint containing 10 withdrawal intents, each `OperatorSelection::any()`.
/// 3. Verify 10 assignments exist and at least 2 distinct operators are represented.
///
/// Sizing rationale: 10 intents × 10 operators puts the probability of all draws
/// colliding on a single operator at ~10^-9, so the test stays seed-agnostic without
/// being flaky.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_intents_in_one_checkpoint_spread_across_operators() {
    use std::collections::HashSet;

    let num_operators = 10;
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .num_operators(num_operators)
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // Arrange: 10 deposits across a 10-operator notary set.
    let num_deposits = 10u32;
    harness.submit_deposits(&ctx, num_deposits).await.unwrap();

    // Act: one checkpoint carrying 10 "any"-operator intents.
    let intents: Vec<(u64, OperatorSelection)> = (0..num_deposits)
        .map(|_| (denomination, OperatorSelection::any()))
        .collect();
    harness
        .submit_checkpoint_with_withdrawal_intents(&mut checkpoint_harness, &intents)
        .await
        .unwrap();

    // Assert: every intent produced an assignment, spread across more than one operator.
    let bridge_state = harness.bridge_state().unwrap();
    assert_eq!(
        bridge_state.assignments().len(),
        num_deposits,
        "every intent should produce an assignment"
    );
    let assignees: Vec<_> = bridge_state
        .assignments()
        .assignments()
        .iter()
        .map(|a| a.current_assignee())
        .collect();
    let unique: HashSet<_> = assignees.iter().copied().collect();
    assert!(
        unique.len() > 1,
        "expected intents in one checkpoint to spread across multiple operators, got {assignees:?}",
    );
}
