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
use strata_asm_admin_types::Role;
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
        .pending_predicate_transitions()
        .unwrap()
        .first()
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
        !harness.pending_predicate_transitions().unwrap().is_empty(),
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
        !harness.pending_predicate_transitions().unwrap().is_empty(),
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

    // Assert: the pending predicate becomes active and the queue is emptied.
    assert_eq!(
        harness.checkpoint_tip_update_logs().unwrap(),
        vec![successor_tip],
        "a checkpoint starting at B+1 should be accepted under the successor predicate"
    );
    let checkpoint_state = harness.checkpoint_state().unwrap();
    assert_eq!(checkpoint_state.checkpoint_predicate(), &new_predicate);
    assert!(
        harness.pending_predicate_transitions().unwrap().is_empty(),
        "promoting the transition should empty the pending queue"
    );
}

/// Enacts two rotations before checkpoint progress and verifies every resulting territory.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_rotations_select_old_intermediate_and_latest_keys() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|config| config.confirmation_depths.ol_stf_vk_update = 0)
        .build()
        .await;

    let old_predicate = checkpoint_harness.checkpoint_predicate();
    let first_signer = CheckpointTestHarness::mint_checkpoint_signer();
    let first_predicate = first_signer.predicate();
    let first_enactment_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(first_predicate.clone()))
        .await
        .unwrap();
    let first_boundary = harness
        .commitment_of(first_enactment_block)
        .await
        .unwrap()
        .height();

    let second_signer = CheckpointTestHarness::mint_checkpoint_signer();
    let second_predicate = second_signer.predicate();
    let second_enactment_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(second_predicate.clone()))
        .await
        .unwrap();
    let second_boundary = harness
        .commitment_of(second_enactment_block)
        .await
        .unwrap()
        .height();

    let enactments = harness.pending_predicate_transitions().unwrap();
    assert_eq!(enactments.len(), 2);
    assert_eq!(enactments[0].boundary(), first_boundary);
    assert_eq!(enactments[0].predicate(), &first_predicate);
    assert_eq!(enactments[1].boundary(), second_boundary);
    assert_eq!(enactments[1].predicate(), &second_predicate);
    assert_eq!(
        harness.admin_state().unwrap().ol_pending_transition_count(),
        2
    );
    assert_eq!(
        harness
            .find_log_in_blocks::<CheckpointPredicateEnacted>(&[first_enactment_block])
            .await
            .unwrap()
            .unwrap()
            .new_predicate(),
        &first_predicate
    );
    assert_eq!(
        harness
            .find_log_in_blocks::<CheckpointPredicateEnacted>(&[second_enactment_block])
            .await
            .unwrap()
            .unwrap()
            .new_predicate(),
        &second_predicate
    );

    // A checkpoint spanning the first boundary is rejected under both adjacent keys.
    harness.mine_block(None).await.unwrap();
    let initial_tip = *checkpoint_harness.verified_tip();
    let straddling_tip = next_checkpoint_tip(&checkpoint_harness, first_boundary + 1);
    let old_key_straddle = harness
        .build_checkpoint_tx_for_tip(&checkpoint_harness, straddling_tip, vec![])
        .await
        .unwrap();
    harness.submit_and_mine_tx(&old_key_straddle).await.unwrap();
    let first_key_straddle = harness
        .build_checkpoint_tx_for_tip_signed_by(
            &checkpoint_harness,
            straddling_tip,
            vec![],
            &first_signer,
        )
        .await
        .unwrap();
    harness
        .submit_and_mine_tx(&first_key_straddle)
        .await
        .unwrap();
    assert_eq!(
        harness.checkpoint_state().unwrap().verified_tip(),
        &initial_tip,
        "straddling proofs under either adjacent key must be rejected"
    );

    // The old key governs through the first boundary.
    let old_tip = next_checkpoint_tip(&checkpoint_harness, first_boundary);
    let old_tx = harness
        .build_checkpoint_tx_for_tip(&checkpoint_harness, old_tip, vec![])
        .await
        .unwrap();
    harness.submit_and_mine_tx(&old_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(old_tip);
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &old_predicate
    );
    assert_eq!(harness.pending_predicate_transitions().unwrap().len(), 2);

    // The first key governs the intermediate territory through the second boundary.
    let intermediate_tip = next_checkpoint_tip(&checkpoint_harness, second_boundary);
    let intermediate_tx = harness
        .build_checkpoint_tx_for_tip_signed_by(
            &checkpoint_harness,
            intermediate_tip,
            vec![],
            &first_signer,
        )
        .await
        .unwrap();
    harness.submit_and_mine_tx(&intermediate_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(intermediate_tip);
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &first_predicate
    );
    let remaining = harness.pending_predicate_transitions().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].predicate(), &second_predicate);

    // The latest key governs after the second boundary and clears the queue on promotion.
    let latest_tip = next_checkpoint_tip(&checkpoint_harness, second_boundary + 1);
    let latest_tx = harness
        .build_checkpoint_tx_for_tip_signed_by(
            &checkpoint_harness,
            latest_tip,
            vec![],
            &second_signer,
        )
        .await
        .unwrap();
    harness.submit_and_mine_tx(&latest_tx).await.unwrap();
    checkpoint_harness.update_verified_tip(latest_tip);
    assert_eq!(
        harness.checkpoint_state().unwrap().checkpoint_predicate(),
        &second_predicate
    );
    assert!(harness.pending_predicate_transitions().unwrap().is_empty());

    // Checkpoint emits the acknowledgement during PROCESS. Administration consumes it in the
    // subsequent FINISH stage of the same transition, before the state sections are exported.
    assert_eq!(
        harness.admin_state().unwrap().ol_pending_transition_count(),
        0
    );
}

/// The full worker persists exactly 32 delayed OL rotations and rejects the next action
/// without advancing administration replay state.
#[tokio::test(flavor = "multi_thread")]
async fn test_delayed_ol_rotation_queue_admits_32_and_rejects_33rd() {
    const DELAY: u16 = 100;
    let Setup {
        harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|config| config.confirmation_depths.ol_stf_vk_update = DELAY)
        .build()
        .await;

    for _ in 0..32 {
        let predicate = CheckpointTestHarness::mint_checkpoint_signer().predicate();
        harness
            .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(predicate))
            .await
            .unwrap();
    }
    let admitted_state = harness.admin_state().unwrap();
    assert_eq!(admitted_state.pending_ol_stf_vk_update_count(), 32);
    let next_update_id = admitted_state.next_update_id();
    let last_seqno = admitted_state
        .authority(Role::StrataAdministrator)
        .unwrap()
        .last_seqno();

    let rejected_predicate = CheckpointTestHarness::mint_checkpoint_signer().predicate();
    harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(rejected_predicate))
        .await
        .unwrap();
    let rejected_state = harness.admin_state().unwrap();
    assert_eq!(rejected_state.pending_ol_stf_vk_update_count(), 32);
    assert_eq!(rejected_state.next_update_id(), next_update_id);
    assert_eq!(
        rejected_state
            .authority(Role::StrataAdministrator)
            .unwrap()
            .last_seqno(),
        last_seqno
    );
}

/// The full worker rejects a distinct 33rd rotation before it consumes replay state, so every
/// accepted update is guaranteed to reach checkpoint and emit an enactment log.
#[tokio::test(flavor = "multi_thread")]
async fn test_full_checkpoint_capacity_rejects_33rd_before_enactment() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .customize_admin(|config| config.confirmation_depths.ol_stf_vk_update = 0)
        .build()
        .await;

    for _ in 0..32 {
        let predicate = CheckpointTestHarness::mint_checkpoint_signer().predicate();
        harness
            .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(predicate))
            .await
            .unwrap();
    }

    let admitted_transitions = harness.pending_predicate_transitions().unwrap();
    assert_eq!(admitted_transitions.len(), 32);
    let admitted_admin_state = harness.admin_state().unwrap();
    assert_eq!(admitted_admin_state.ol_pending_transition_count(), 32);
    let next_update_id = admitted_admin_state.next_update_id();
    let last_seqno = admitted_admin_state
        .authority(Role::StrataAdministrator)
        .unwrap()
        .last_seqno();

    let rejected_predicate = CheckpointTestHarness::mint_checkpoint_signer().predicate();
    let rejected_block = harness
        .submit_admin_action(&mut admin_ctx, ol_stf_vk_update(rejected_predicate))
        .await
        .unwrap();

    assert_eq!(
        harness.pending_predicate_transitions().unwrap(),
        admitted_transitions,
        "the rejected update must not reach checkpoint state"
    );
    assert!(
        harness
            .find_log_in_blocks::<CheckpointPredicateEnacted>(&[rejected_block])
            .await
            .unwrap()
            .is_none(),
        "the rejected update must not emit an enactment log"
    );
    let rejected_admin_state = harness.admin_state().unwrap();
    assert_eq!(rejected_admin_state.ol_pending_transition_count(), 32);
    assert_eq!(rejected_admin_state.next_update_id(), next_update_id);
    assert_eq!(
        rejected_admin_state
            .authority(Role::StrataAdministrator)
            .unwrap()
            .last_seqno(),
        last_seqno
    );
}
