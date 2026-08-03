//! End-to-end checkpoint predicate handover tests.
//!
//! Exercises range-keyed predicate selection through a real bitcoind and the full ASM worker:
//! which key verifies a checkpoint is decided by the L1 territory the checkpoint covers.
//!
//! Companion to `admin_to_checkpoint.rs`, which covers the other half of the same feature —
//! how an admin enactment propagates into checkpoint state. The split is by question, not by
//! subprotocol: propagation there, selection here.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{ol_stf_vk_update, AdminExt, DEFAULT_CONFIRMATION_DEPTH},
    checkpoint::CheckpointExt,
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_checkpoint_types::CheckpointTip;
use strata_asm_logs::CheckpointPredicateEnacted;
use strata_identifiers::{OLBlockCommitment, OLBlockId};
use strata_test_utils_arb::ArbitraryGenerator;
use strata_test_utils_checkpoint::CheckpointTestHarness;

fn next_checkpoint_tip(
    checkpoint_harness: &CheckpointTestHarness,
    l1_height: u32,
) -> CheckpointTip {
    let verified_tip = checkpoint_harness.verified_tip();
    let ol_blkid: OLBlockId = ArbitraryGenerator::new().generate();
    let ol_commitment = OLBlockCommitment::new(verified_tip.l2_commitment().slot() + 1, ol_blkid);
    CheckpointTip::new(verified_tip.epoch + 1, l1_height, ol_commitment)
}

/// Verifies the complete range-keyed predicate handover through the live ASM path.
///
/// The straddling rejection deliberately comes before either accepted checkpoint so it is
/// attributable to the predicate boundary, not L1 non-regression.
#[tokio::test(flavor = "multi_thread")]
async fn test_full_predicate_handover_selects_key_by_l1_range() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    // Arrange: enact a predicate rotation at boundary B and preserve the initial active key.
    let old_predicate = checkpoint_harness.checkpoint_predicate();
    let new_signer = CheckpointTestHarness::mint_checkpoint_signer();
    let new_predicate = new_signer.predicate();
    harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();
    let enactment_blocks = harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();
    let enactment = harness
        .find_log_in_blocks::<CheckpointPredicateEnacted>(&enactment_blocks)
        .await
        .unwrap()
        .expect("predicate rotation should emit an enactment log");
    let boundary = harness
        .pending_predicate_transition()
        .unwrap()
        .expect("enactment should record a pending transition")
        .boundary();
    assert_eq!(enactment.new_predicate(), &new_predicate);
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &old_predicate,
        "enactment should not immediately replace the active predicate"
    );

    // Arrange: advance L1 beyond B+1 so a straddling tip passes the current-height check.
    harness.mine_block(None).await.unwrap();
    let initial_verified_tip = *checkpoint_harness.verified_tip();

    // Act: first submit a checkpoint covering both sides of B, under each key in turn.
    //
    // Submitting under both is what makes this a straddle test rather than a key-mismatch test.
    // Rejecting only the old-key proof would also happen if the range were wrongly verified
    // against the successor key throughout, so that alone proves nothing; and rejecting only the
    // successor-key proof would also happen if the range were wrongly verified against the active
    // key throughout. Only the straddle rule rejects both.
    let straddling_tip = next_checkpoint_tip(&checkpoint_harness, boundary + 1);
    let straddling_tx = harness
        .build_checkpoint_tx_for_tip(&checkpoint_harness, straddling_tip, vec![])
        .await
        .unwrap();
    harness.submit_and_mine_tx(&straddling_tx).await.unwrap();
    let straddling_tx_successor_key = harness
        .build_checkpoint_tx_for_tip_signed_by(
            &checkpoint_harness,
            straddling_tip,
            vec![],
            &new_signer,
        )
        .await
        .unwrap();
    harness
        .submit_and_mine_tx(&straddling_tx_successor_key)
        .await
        .unwrap();

    // Assert: neither straddling checkpoint is accepted, and the tip has not advanced.
    assert!(
        harness.checkpoint_tip_update_logs().unwrap().is_empty(),
        "a checkpoint straddling the predicate boundary must emit no tip-update log under \
         either the active or the queued predicate"
    );
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(
        checkpoint_state.verified_tip(),
        &initial_verified_tip,
        "a straddling checkpoint must not advance the verified tip"
    );
    assert!(
        harness.pending_predicate_transition().unwrap().is_some(),
        "the transition must remain pending after a straddling rejection"
    );

    // Act: submit a checkpoint terminating exactly at B under the old predicate.
    let preceding_tip = next_checkpoint_tip(&checkpoint_harness, boundary);
    let preceding_tx = harness
        .build_checkpoint_tx_for_tip(&checkpoint_harness, preceding_tip, vec![])
        .await
        .unwrap();
    harness.submit_and_mine_tx(&preceding_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(preceding_tip);

    // Assert: the preceding-key checkpoint is accepted without promoting the transition.
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap(),
        vec![preceding_tip],
        "a checkpoint ending at B should be accepted under the preceding predicate"
    );
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(checkpoint_state.checkpoint_predicate(), &old_predicate);
    assert!(
        harness.pending_predicate_transition().unwrap().is_some(),
        "a checkpoint ending at B must not promote the transition"
    );

    // Act: submit a checkpoint starting at B+1 under the new predicate.
    let successor_tip = next_checkpoint_tip(&checkpoint_harness, boundary + 1);
    let successor_tx = harness
        .build_checkpoint_tx_for_tip_signed_by(
            &checkpoint_harness,
            successor_tip,
            vec![],
            &new_signer,
        )
        .await
        .unwrap();
    harness.submit_and_mine_tx(&successor_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(successor_tip);

    // Assert: the pending predicate becomes active and the slot is freed.
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap(),
        vec![successor_tip],
        "a checkpoint starting at B+1 should be accepted under the successor predicate"
    );
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(checkpoint_state.checkpoint_predicate(), &new_predicate);
    assert!(
        harness.pending_predicate_transition().unwrap().is_none(),
        "promoting the transition should free the pending slot"
    );
}

/// Verifies the one-rotation-at-a-time rule through the full worker.
///
/// A second rotation is refused while the first is still outstanding, and only becomes
/// authorizable again once a checkpoint promotes the first and administration observes the
/// acknowledgement. Driving it through the worker is what makes this meaningful: the refusal
/// spans the PROCESS-phase enactment and the FINISH-phase acknowledgement, which the
/// subprotocol unit tests exercise only in isolation.
#[tokio::test(flavor = "multi_thread")]
async fn test_second_rotation_refused_until_checkpoint_promotes_the_first() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|config| config.confirmation_depths.ol_stf_vk_update = 0)
        .build()
        .await;

    // Arrange: enact the first rotation immediately, at boundary B.
    let first_signer = CheckpointTestHarness::mint_checkpoint_signer();
    let first_predicate = first_signer.predicate();
    let enactment_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(first_predicate.clone()))
        .await
        .unwrap();
    let boundary = harness
        .commitment_of(enactment_block)
        .await
        .unwrap()
        .height();
    let enactment = harness
        .find_log_in_blocks::<CheckpointPredicateEnacted>(&[enactment_block])
        .await
        .unwrap()
        .expect("the first rotation should emit an enactment log");
    assert_eq!(enactment.new_predicate(), &first_predicate);
    assert_eq!(
        harness
            .pending_predicate_transition()
            .unwrap()
            .map(|transition| transition.boundary()),
        Some(boundary)
    );

    // Act: authorize a second rotation while the first still awaits activation.
    let second_signer = CheckpointTestHarness::mint_checkpoint_signer();
    let second_predicate = second_signer.predicate();
    let rejected_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(second_predicate.clone()))
        .await
        .unwrap();

    // Assert: nothing was announced, recorded, or queued for later.
    assert!(
        harness
            .find_log_in_blocks::<CheckpointPredicateEnacted>(&[rejected_block])
            .await
            .unwrap()
            .is_none(),
        "a refused rotation must not announce an enactment"
    );
    assert_eq!(
        harness
            .pending_predicate_transition()
            .unwrap()
            .map(|transition| transition.predicate().clone()),
        Some(first_predicate.clone()),
        "the pending slot must still hold the first rotation"
    );
    let admin_state = harness.admin_state().unwrap();
    assert!(
        admin_state.queued().is_empty(),
        "a refused rotation must not linger in the admin queue"
    );
    assert!(
        admin_state.ol_transition_pending(),
        "the first rotation should still be marked outstanding"
    );

    // Arrange: walk the verified tip up to exactly B under the active key. Without this the
    // promoting checkpoint below would cover genesis+1..=B+1 and be rejected as a straddle.
    harness.mine_block(None).await.unwrap();
    let preceding_tip = next_checkpoint_tip(&checkpoint_harness, boundary);
    let preceding_tx = harness
        .build_checkpoint_tx_for_tip(&checkpoint_harness, preceding_tip, vec![])
        .await
        .unwrap();
    harness.submit_and_mine_tx(&preceding_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(preceding_tip);
    assert!(
        harness.pending_predicate_transition().unwrap().is_some(),
        "a checkpoint ending at B must not promote the transition"
    );

    // Act: accept a checkpoint starting at B+1 so the first rotation is promoted.
    let promoting_tip = next_checkpoint_tip(&checkpoint_harness, boundary + 1);
    let promoting_tx = harness
        .build_checkpoint_tx_for_tip_signed_by(
            &checkpoint_harness,
            promoting_tip,
            vec![],
            &first_signer,
        )
        .await
        .unwrap();
    harness.submit_and_mine_tx(&promoting_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(promoting_tip);

    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &first_predicate
    );
    assert!(
        harness.pending_predicate_transition().unwrap().is_none(),
        "promotion should free the pending slot"
    );

    // Act: the same second rotation is now authorizable.
    let admission_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(second_predicate.clone()))
        .await
        .unwrap();

    // Assert: it enacts at a strictly later boundary than the first.
    let admitted = harness
        .find_log_in_blocks::<CheckpointPredicateEnacted>(&[admission_block])
        .await
        .unwrap()
        .expect("the second rotation should enact once the slot is free");
    assert_eq!(admitted.new_predicate(), &second_predicate);
    let later_boundary = harness
        .pending_predicate_transition()
        .unwrap()
        .expect("the second rotation should occupy the pending slot")
        .boundary();
    assert_eq!(
        later_boundary,
        harness
            .commitment_of(admission_block)
            .await
            .unwrap()
            .height()
    );
    assert!(
        later_boundary > boundary,
        "the second boundary {later_boundary} must be later than the first {boundary}"
    );
}
