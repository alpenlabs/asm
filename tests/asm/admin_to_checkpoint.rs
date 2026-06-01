//! Admin → Checkpoint subprotocol interaction tests
//!
//! Tests the propagation of admin updates to the checkpoint subprotocol via interprotocol
//! messaging.
//!
//! Key interactions tested:
//! - Sequencer key update (depth 0) → checkpoint sequencer_predicate adopts the new Bip340Schnorr
//!   key
//! - Multiple sequential sequencer updates → checkpoint ends up with the latest key
//! - Predicate (OL STF VK) update → queued first, then checkpoint checkpoint_predicate adopts it
//!   after activation
//! - Combined depth-0 sequencer + queued predicate → sequencer applies immediately, predicate after
//!   activation
//! - Sequencer update signed by any non-`StrataSequencerManager` role → rejected, checkpoint
//!   sequencer_predicate unchanged
//! - Predicate update signed by any non-`StrataAdministrator` role → rejected, checkpoint
//!   checkpoint_predicate unchanged
//! - Depth-0 sequencer update in the same block as a checkpoint → checkpoint validates against the
//!   old key, then the new key takes effect (order-independent)
//! - Queued sequencer update activating in the same block as a checkpoint → checkpoint validates
//!   against the old key, then the new key takes effect
//! - Depth-0 predicate update in the same block as a checkpoint → checkpoint validates against the
//!   old predicate, then the new predicate takes effect
//! - Queued predicate update activating in the same block as a checkpoint → checkpoint validates
//!   against the old predicate, then the new predicate takes effect
//! - Checkpoint signed by the old sequencer key after the update fully takes effect → rejected, no
//!   tip-update log emitted

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{
        assert_only_required_role_can_send, ol_stf_vk_update, sequencer_update, AdminExt,
        DEFAULT_CONFIRMATION_DEPTH,
    },
    checkpoint::CheckpointExt,
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_predicate::{PredicateKey, PredicateTypeId};

// ============================================================================
// Sequencer Key → Checkpoint Sequencer Predicate
// ============================================================================

/// Verifies sequencer key updates propagate to checkpoint subprotocol.
///
/// Uses confirmation depth 0 for sequencer updates so the propagation can be observed
/// without mining additional blocks for activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_update_propagates_to_checkpoint() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|c| c.confirmation_depths.sequencer_update = 0)
        .build()
        .await;

    // Arrange: capture the initial checkpoint sequencer predicate.
    let initial_sequencer_predicate = harness
        .checkpoint_state()
        .unwrap()
        .sequencer_predicate()
        .clone();

    // Act: submit a (depth-0) sequencer key update.
    let new_key = [42u8; 32];
    harness
        .submit_admin_action(&mut ctx, sequencer_update(new_key))
        .await
        .unwrap();

    // Assert: checkpoint adopts the new Bip340Schnorr sequencer predicate.
    let final_checkpoint_state = harness.checkpoint_state().unwrap();
    assert_ne!(
        final_checkpoint_state.sequencer_predicate(),
        &initial_sequencer_predicate,
        "checkpoint sequencer_predicate should change after a sequencer key update"
    );
    let expected = PredicateKey::new(PredicateTypeId::Bip340Schnorr, new_key.to_vec());
    assert_eq!(
        final_checkpoint_state.sequencer_predicate(),
        &expected,
        "checkpoint should have the new sequencer predicate"
    );
}

/// Verifies multiple sequential sequencer key updates result in checkpoint having the latest key.
///
/// Uses confirmation depth 0 for sequencer updates so each update is applied on inclusion.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_sequencer_updates_checkpoint_has_latest() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|c| c.confirmation_depths.sequencer_update = 0)
        .build()
        .await;

    // Act: three sequencer key updates in sequence (each applies immediately at depth 0).
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let key3 = [3u8; 32];
    harness
        .submit_admin_action(&mut ctx, sequencer_update(key1))
        .await
        .unwrap();
    harness
        .submit_admin_action(&mut ctx, sequencer_update(key2))
        .await
        .unwrap();
    harness
        .submit_admin_action(&mut ctx, sequencer_update(key3))
        .await
        .unwrap();

    // Assert: checkpoint holds the latest key, and all three updates were processed.
    let expected = PredicateKey::new(PredicateTypeId::Bip340Schnorr, key3.to_vec());
    assert_eq!(
        harness.checkpoint_state().unwrap().sequencer_predicate(),
        &expected,
        "checkpoint should have the latest sequencer predicate"
    );
    assert_eq!(
        harness.admin_state().unwrap().next_update_id(),
        3,
        "all 3 updates should be processed"
    );
}

// ============================================================================
// Predicate Update → Checkpoint Predicate
// ============================================================================

/// Verifies predicate (verifying key) updates propagate to checkpoint after activation.
///
/// Flow:
/// 1. Submit predicate update (gets queued)
/// 2. Mine blocks to trigger activation
/// 3. Verify checkpoint's predicate field is updated
#[tokio::test(flavor = "multi_thread")]
async fn test_predicate_update_propagates_to_checkpoint() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    // Arrange.
    let initial_predicate = harness
        .checkpoint_state()
        .unwrap()
        .checkpoint_predicate()
        .clone();

    // Act: submit a predicate (OL STF VK) update — queued for StrataAdministrator.
    let new_predicate = PredicateKey::always_accept();
    harness
        .submit_admin_action(&mut ctx, ol_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();

    // Assert: queued, checkpoint predicate unchanged until activation.
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        1,
        "predicate update should be queued"
    );
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &initial_predicate,
        "checkpoint predicate should not change while the update is queued"
    );

    // Act: mine through the activation window.
    harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    // Assert: checkpoint predicate updated, queue drained.
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &new_predicate,
        "checkpoint predicate should be updated after activation"
    );
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        0,
        "queue should be empty after activation"
    );
}

// ============================================================================
// Combined Updates
// ============================================================================

/// Verifies sequencer key update followed by predicate update both affect checkpoint.
///
/// Tests the interaction between a zero-depth update (sequencer, applied immediately) and a
/// non-zero-depth update (predicate, queued until activation).
#[tokio::test(flavor = "multi_thread")]
async fn test_zero_and_nonzero_depth_updates_both_apply() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|c| c.confirmation_depths.sequencer_update = 0)
        .build()
        .await;

    let initial_predicate = harness
        .checkpoint_state()
        .unwrap()
        .checkpoint_predicate()
        .clone();

    // Act + Assert: depth-0 sequencer update applies immediately.
    let new_sequencer_key = [99u8; 32];
    harness
        .submit_admin_action(&mut ctx, sequencer_update(new_sequencer_key))
        .await
        .unwrap();
    let expected_seq_predicate =
        PredicateKey::new(PredicateTypeId::Bip340Schnorr, new_sequencer_key.to_vec());
    assert_eq!(
        harness.checkpoint_state().unwrap().sequencer_predicate(),
        &expected_seq_predicate,
        "sequencer predicate should be updated immediately at confirmation depth 0"
    );

    // Act: queue a predicate update (non-zero depth).
    let new_predicate = PredicateKey::always_accept();
    harness
        .submit_admin_action(&mut ctx, ol_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &initial_predicate,
        "checkpoint predicate should not change yet (update is queued)"
    );
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        1,
        "predicate update should be queued"
    );

    // Act: mine through the activation window.
    harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    // Assert: both updates now reflected in the checkpoint; queue drained.
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        0,
        "queue should be empty after activation"
    );
    let final_checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        final_checkpoint_state.sequencer_predicate(),
        &expected_seq_predicate,
        "sequencer predicate should still be the new value"
    );
    assert_eq!(
        final_checkpoint_state.checkpoint_predicate(),
        &new_predicate,
        "checkpoint predicate should be updated after activation"
    );
}

// ============================================================================
// Role authorization (negative)
// ============================================================================

/// A sequencer update signed by the wrong role must not touch the checkpoint's sequencer
/// predicate.
///
/// Sequencer updates require `StrataSequencerManager`; the shared helper verifies every other
/// role is rejected at the admin layer, and the call site additionally checks the
/// cross-subprotocol effect (the checkpoint sequencer predicate stays put).
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_update_rejected_from_wrong_role() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial = harness
        .checkpoint_state()
        .unwrap()
        .sequencer_predicate()
        .clone();

    assert_only_required_role_can_send(&harness, &mut ctx, sequencer_update([42u8; 32])).await;

    assert_eq!(
        harness.checkpoint_state().unwrap().sequencer_predicate(),
        &initial,
        "wrong-role sequencer update must not change the checkpoint sequencer predicate",
    );
}

/// An OL STF VK (checkpoint predicate) update signed by any wrong role is rejected and must
/// not touch the checkpoint predicate.
///
/// OL STF VK updates require `StrataAdministrator`; the shared helper verifies every other
/// role is rejected, and the call site checks the checkpoint predicate stays put.
#[tokio::test(flavor = "multi_thread")]
async fn test_predicate_update_rejected_from_wrong_role() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial = harness
        .checkpoint_state()
        .unwrap()
        .checkpoint_predicate()
        .clone();

    assert_only_required_role_can_send(
        &harness,
        &mut ctx,
        ol_stf_vk_update(PredicateKey::always_accept()),
    )
    .await;

    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &initial,
        "wrong-role predicate update must not change the checkpoint predicate",
    );
}

// ============================================================================
// Same-block update + checkpoint: the old value still validates the checkpoint
// ============================================================================
//
// The ASM applies inter-subprotocol messages only after all `process_txs` in a block, so a
// sequencer/predicate update relayed by the admin subprotocol in block N does not affect a
// checkpoint that lands in block N — the old sequencer/predicate still validates it, and the
// update takes effect only once the block's transactions are fully processed.

/// Drives the immediate (depth-0) sequencer-update + checkpoint same-block scenario, mining
/// the two transactions in the given order to show the outcome is order-independent.
async fn run_immediate_sequencer_same_block(admin_first: bool) {
    let Setup {
        harness,
        admin: mut ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|c| c.confirmation_depths.sequencer_update = 0)
        .build()
        .await;

    // Build up some processed L1 history so the checkpoint covers a real L1 range.
    harness.mine_blocks(2).await.unwrap();

    let new_key = [42u8; 32];
    let admin_tx = harness
        .build_admin_action_tx(&mut ctx, sequencer_update(new_key))
        .await
        .unwrap();
    let (cp_tx, cp_tip) = harness
        .build_checkpoint_tx(&checkpoint_harness, vec![])
        .await
        .unwrap();

    let ordered = if admin_first {
        vec![admin_tx, cp_tx]
    } else {
        vec![cp_tx, admin_tx]
    };
    harness.mine_block_with_ordered_txs(&ordered).await.unwrap();
    checkpoint_harness.update_verified_tip(cp_tip);

    let cp_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        cp_state.verified_tip().epoch,
        1,
        "checkpoint should be accepted in the same block as the sequencer update (admin_first={admin_first})"
    );
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap().len(),
        1,
        "exactly one tip-update log should be emitted"
    );

    let expected = PredicateKey::new(PredicateTypeId::Bip340Schnorr, new_key.to_vec());
    assert_eq!(
        cp_state.sequencer_predicate(),
        &expected,
        "sequencer predicate should be updated once the block's transactions are processed"
    );
}

/// Depth-0 sequencer update mined before the checkpoint in the same block.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_immediate_update_same_block_checkpoint_validates_admin_first() {
    run_immediate_sequencer_same_block(true).await;
}

/// Depth-0 sequencer update mined after the checkpoint in the same block (same outcome).
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_immediate_update_same_block_checkpoint_validates_checkpoint_first() {
    run_immediate_sequencer_same_block(false).await;
}

/// A queued sequencer update that activates in the same block as a checkpoint still validates
/// that checkpoint against the old sequencer predicate; the new key takes effect afterward.
#[tokio::test(flavor = "multi_thread")]
async fn test_queued_sequencer_update_activation_same_block_checkpoint_validates() {
    const DEPTH: u64 = DEFAULT_CONFIRMATION_DEPTH as u64;
    let Setup {
        harness,
        admin: mut ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    harness.mine_blocks(2).await.unwrap();

    // Queue a sequencer update; it activates `DEPTH` blocks after the block it lands in.
    let new_key = [7u8; 32];
    harness
        .submit_admin_action(&mut ctx, sequencer_update(new_key))
        .await
        .unwrap();
    let activation = harness.get_processed_height().unwrap() + DEPTH;
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        1,
        "sequencer update should be queued"
    );

    // Build the checkpoint now, advance to the block just before activation (which also confirms
    // the checkpoint's funding), and finally land the checkpoint in the activation block.
    let (cp_tx, cp_tip) = harness
        .build_checkpoint_tx(&checkpoint_harness, vec![])
        .await
        .unwrap();
    harness.mine_until_processed(activation - 1).await.unwrap();
    harness.submit_and_mine_tx(&cp_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(cp_tip);

    let cp_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        cp_state.verified_tip().epoch,
        1,
        "checkpoint should be accepted in the activation block, validated against the old sequencer"
    );
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap().len(),
        1,
        "exactly one tip-update log should be emitted"
    );
    let expected = PredicateKey::new(PredicateTypeId::Bip340Schnorr, new_key.to_vec());
    assert_eq!(
        cp_state.sequencer_predicate(),
        &expected,
        "sequencer predicate should be updated after the activation block"
    );
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        0,
        "queue should be empty after activation"
    );
}

/// A depth-0 checkpoint-predicate update in the same block as a checkpoint validates that
/// checkpoint against the old predicate; the new predicate takes effect afterward.
#[tokio::test(flavor = "multi_thread")]
async fn test_predicate_immediate_update_same_block_checkpoint_validates() {
    let Setup {
        harness,
        admin: mut ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|c| c.confirmation_depths.ol_stf_vk_update = 0)
        .build()
        .await;

    harness.mine_blocks(2).await.unwrap();

    let initial_predicate = harness
        .checkpoint_state()
        .unwrap()
        .checkpoint_predicate()
        .clone();
    let new_predicate = PredicateKey::always_accept();

    let admin_tx = harness
        .build_admin_action_tx(&mut ctx, ol_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();
    let (cp_tx, cp_tip) = harness
        .build_checkpoint_tx(&checkpoint_harness, vec![])
        .await
        .unwrap();

    harness
        .mine_block_with_ordered_txs(&[cp_tx, admin_tx])
        .await
        .unwrap();
    checkpoint_harness.update_verified_tip(cp_tip);

    let cp_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        cp_state.verified_tip().epoch,
        1,
        "checkpoint should be accepted, validated against the old checkpoint predicate"
    );
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap().len(),
        1,
        "exactly one tip-update log should be emitted"
    );
    assert_ne!(
        cp_state.checkpoint_predicate(),
        &initial_predicate,
        "checkpoint predicate should change after the block"
    );
    assert_eq!(
        cp_state.checkpoint_predicate(),
        &new_predicate,
        "checkpoint predicate should be the new value after the block"
    );
}

/// A queued checkpoint-predicate update that activates in the same block as a checkpoint still
/// validates that checkpoint against the old predicate; the new predicate takes effect after.
#[tokio::test(flavor = "multi_thread")]
async fn test_queued_predicate_update_activation_same_block_checkpoint_validates() {
    const DEPTH: u64 = DEFAULT_CONFIRMATION_DEPTH as u64;
    let Setup {
        harness,
        admin: mut ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    harness.mine_blocks(2).await.unwrap();

    let new_predicate = PredicateKey::always_accept();

    harness
        .submit_admin_action(&mut ctx, ol_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();
    let activation = harness.get_processed_height().unwrap() + DEPTH;
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        1,
        "predicate update should be queued"
    );

    let (cp_tx, cp_tip) = harness
        .build_checkpoint_tx(&checkpoint_harness, vec![])
        .await
        .unwrap();
    harness.mine_until_processed(activation - 1).await.unwrap();
    harness.submit_and_mine_tx(&cp_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(cp_tip);

    let cp_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        cp_state.verified_tip().epoch,
        1,
        "checkpoint should be accepted in the activation block, validated against the old predicate"
    );
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap().len(),
        1,
        "exactly one tip-update log should be emitted"
    );
    assert_eq!(
        cp_state.checkpoint_predicate(),
        &new_predicate,
        "checkpoint predicate should be updated after the activation block"
    );
    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        0,
        "queue should be empty after activation"
    );
}

/// Once a sequencer update has fully taken effect, a checkpoint signed by the old sequencer
/// key in a later block is rejected — confirming the new key genuinely takes over.
#[tokio::test(flavor = "multi_thread")]
async fn test_checkpoint_signed_by_old_sequencer_rejected_after_update() {
    let Setup {
        harness,
        admin: mut ctx,
        checkpoint: checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|c| c.confirmation_depths.sequencer_update = 0)
        .build()
        .await;

    harness.mine_blocks(2).await.unwrap();

    // Apply the sequencer update (depth 0) in its own block — fully in effect afterward.
    harness
        .submit_admin_action(&mut ctx, sequencer_update([42u8; 32]))
        .await
        .unwrap();

    // A checkpoint signed by the harness's (now stale) sequencer key lands in a later block.
    let (cp_tx, _cp_tip) = harness
        .build_checkpoint_tx(&checkpoint_harness, vec![])
        .await
        .unwrap();
    harness.submit_and_mine_tx(&cp_tx).await.unwrap();

    let cp_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        cp_state.verified_tip().epoch,
        0,
        "a checkpoint signed by the old sequencer key must be rejected after the update"
    );
    assert!(
        harness.checkpoint_tip_update_logs().unwrap().is_empty(),
        "a rejected checkpoint must not emit a tip-update log"
    );
}
