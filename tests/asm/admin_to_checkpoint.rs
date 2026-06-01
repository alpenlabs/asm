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

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{ol_stf_vk_update, sequencer_update, AdminExt, DEFAULT_CONFIRMATION_DEPTH},
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
