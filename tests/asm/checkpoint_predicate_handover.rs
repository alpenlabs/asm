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

    // Arrange: queue a predicate rotation at boundary B and preserve the initial active key.
    let old_predicate = checkpoint_harness.checkpoint_predicate();
    let new_signer = CheckpointTestHarness::mint_checkpoint_signer();
    let new_predicate = new_signer.predicate();
    harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();
    let queueing_blocks = harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();
    let boundary = harness
        .pending_predicate_transition()
        .unwrap()
        .expect("the rotation should record a pending transition")
        .boundary();
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &old_predicate,
        "queueing a rotation should not immediately replace the active predicate"
    );
    assert!(
        harness
            .find_log_in_blocks::<CheckpointPredicateEnacted>(&queueing_blocks)
            .await
            .unwrap()
            .is_none(),
        "a rotation that governs nothing yet must not be announced"
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

    // Act: submit a checkpoint terminating exactly at B under the old predicate. Reaching B
    // is what activates the successor: every height a later checkpoint can claim lies past
    // the boundary, so the successor already governs all of them.
    let preceding_tip = next_checkpoint_tip(&checkpoint_harness, boundary);
    let preceding_tx = harness
        .build_checkpoint_tx_for_tip(&checkpoint_harness, preceding_tip, vec![])
        .await
        .unwrap();
    let preceding_block = harness.submit_and_mine_tx(&preceding_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(preceding_tip);

    // Assert: the preceding-key checkpoint is accepted under the old predicate, and reaching
    // B activates the successor and announces it.
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap(),
        vec![preceding_tip],
        "a checkpoint ending at B should be accepted under the preceding predicate"
    );
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(checkpoint_state.checkpoint_predicate(), &new_predicate);
    assert!(
        harness.pending_predicate_transition().unwrap().is_none(),
        "a checkpoint reaching B should promote the transition"
    );
    let announcement = harness
        .find_log_in_blocks::<CheckpointPredicateEnacted>(&[preceding_block])
        .await
        .unwrap()
        .expect("the block whose checkpoint activates the rotation should announce it");
    assert_eq!(announcement.new_predicate(), &new_predicate);

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

    // Assert: the territory past B really is governed by the successor predicate.
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap(),
        vec![successor_tip],
        "a checkpoint starting at B+1 should be accepted under the successor predicate"
    );
    assert_ne!(old_predicate, new_predicate);
}

/// Verifies the per-block rotation limit and the queueing that follows from it.
///
/// Two rotations in one block leave only the first; a rotation in a later block joins the
/// queue behind it, at a strictly later boundary. Driving it through the worker is what
/// makes this meaningful: the admin limit and the checkpoint queue are enforced in different
/// subprotocols, which the unit tests exercise only in isolation.
#[tokio::test(flavor = "multi_thread")]
async fn test_rotations_are_capped_per_block_and_queue_across_blocks() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|config| config.confirmation_depths.ol_stf_vk_update = 0)
        .build()
        .await;

    // Act: two rotations in one block. Zero confirmation depth makes both enact on arrival,
    // so the limit is the only thing separating them.
    for _ in 0..2 {
        let predicate = CheckpointTestHarness::mint_checkpoint_signer().predicate();
        let action = ol_stf_vk_update(predicate);
        let payload = admin_ctx.sign(&action);
        let tx = harness
            .build_envelope_tx(action.tag(), payload)
            .await
            .unwrap();
        harness.submit_transaction(&tx).await.unwrap();
    }
    let shared_block = harness.mine_block(None).await.unwrap();
    let first_boundary = harness.commitment_of(shared_block).await.unwrap().height();

    // Assert: exactly one of the two is queued. Which one is not asserted: that follows from
    // the order bitcoind puts them in the block, not from anything the ASM decides.
    let pending = harness.pending_predicate_transitions().unwrap();
    assert_eq!(
        pending.len(),
        1,
        "a block may queue at most one OL rotation"
    );
    let accepted = pending[0].predicate().clone();

    // Act: a third rotation in a later block, while the first still awaits activation.
    let queued_behind = CheckpointTestHarness::mint_checkpoint_signer().predicate();
    let later_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(queued_behind.clone()))
        .await
        .unwrap();
    let second_boundary = harness.commitment_of(later_block).await.unwrap().height();

    // Assert: it queues behind the first, at a strictly later boundary.
    let pending = harness.pending_predicate_transitions().unwrap();
    assert_eq!(
        pending
            .iter()
            .map(|transition| (transition.predicate().clone(), transition.boundary()))
            .collect::<Vec<_>>(),
        vec![(accepted, first_boundary), (queued_behind, second_boundary)],
        "rotations in separate blocks queue in order, by boundary"
    );
    assert!(first_boundary < second_boundary);
}
