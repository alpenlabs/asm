//! Admin → Bridge subprotocol interaction tests
//!
//! Tests the propagation of operator set updates and defcon signals from the admin
//! subprotocol to the bridge subprotocol via interprotocol messaging.
//!
//! Key interactions tested:
//! - Operator additions → bridge operator table gains new members
//! - Operator removals → bridge operator table deactivates members
//! - Combined add/remove → both applied atomically after activation
//! - Defcon1 from the security council → bridge activates the safe harbour immediately
//! - Defcon3 from the security council → bridge activates the safe harbour after the timelock
//! - Defcon1/Defcon3 signed by any other role → rejected, bridge unchanged
//! - Safe harbour address rotation from the strata administrator → bridge adopts new address
//! - Safe harbour address rotation signed by any other role → rejected, bridge unchanged
//! - Safe harbour address rotation after activation → rejected, bridge address unchanged

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{
        assert_only_required_role_can_send, defcon1_update, defcon3_update, operator_set_update,
        safe_harbour_address_update, submit_and_activate, AdminExt,
    },
    bridge::BridgeExt,
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_proto_bridge_v1_txs::test_utils::create_test_operators;
use strata_asm_proto_bridge_v1_types::SafeHarbourAddress;
use strata_test_utils_arb::ArbitraryGenerator;

// ============================================================================
// Operator Set Updates → Bridge Operator Table
// ============================================================================

/// Verifies that adding an operator via admin propagates to the bridge after activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_add_propagates_to_bridge() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    assert_eq!(
        harness.bridge_state().unwrap().operators().len(),
        3,
        "bridge should start with 3 operators"
    );

    let (_, new_pubkeys) = create_test_operators(1);
    submit_and_activate(
        &harness,
        &mut ctx,
        operator_set_update(vec![new_pubkeys[0]], vec![]),
    )
    .await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(
        bridge.operators().len(),
        4,
        "bridge should have 4 operators after the add activates"
    );
    assert!(
        bridge.operators().is_in_current_multisig(3),
        "the newly added operator (index 3) should be in the current multisig"
    );
}

/// Verifies that removing an operator via admin propagates to the bridge after activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_remove_propagates_to_bridge() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial_agg_key = *harness.bridge_state().unwrap().operators().agg_key();

    submit_and_activate(&harness, &mut ctx, operator_set_update(vec![], vec![0])).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(
        !bridge.operators().is_in_current_multisig(0),
        "operator 0 should be removed from the current multisig"
    );
    assert!(
        bridge.operators().is_in_current_multisig(1),
        "operator 1 should remain"
    );
    assert!(
        bridge.operators().is_in_current_multisig(2),
        "operator 2 should remain"
    );
    assert_ne!(
        *bridge.operators().agg_key(),
        initial_agg_key,
        "aggregate key should change after an operator is removed"
    );
}

/// Verifies combined add and remove in a single operator set update.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_add_and_remove_propagates_to_bridge() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial_agg_key = *harness.bridge_state().unwrap().operators().agg_key();

    let (_, new_pubkeys) = create_test_operators(1);
    submit_and_activate(
        &harness,
        &mut ctx,
        operator_set_update(vec![new_pubkeys[0]], vec![1]),
    )
    .await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(
        bridge.operators().len(),
        4,
        "bridge should have 4 operators after the combined add/remove activates"
    );
    assert!(
        bridge.operators().is_in_current_multisig(0),
        "operator 0 should remain"
    );
    assert!(
        !bridge.operators().is_in_current_multisig(1),
        "operator 1 should be removed"
    );
    assert!(
        bridge.operators().is_in_current_multisig(2),
        "operator 2 should remain"
    );
    assert!(
        bridge.operators().is_in_current_multisig(3),
        "the newly added operator (index 3) should be present"
    );
    assert_ne!(
        *bridge.operators().agg_key(),
        initial_agg_key,
        "aggregate key should change after the combined update"
    );
}

/// Verifies the update is queued and does not affect the bridge until activated.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_update_does_not_apply_before_activation() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let (_, new_pubkeys) = create_test_operators(1);

    // Submit but do NOT mine enough blocks to activate.
    harness
        .submit_admin_action(&mut ctx, operator_set_update(vec![new_pubkeys[0]], vec![]))
        .await
        .unwrap();

    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        1,
        "operator update should be queued"
    );
    assert_eq!(
        harness.bridge_state().unwrap().operators().len(),
        3,
        "bridge should be unchanged while the update is queued"
    );
}

// ============================================================================
// Defcon Signals → Bridge Safe Harbour
// ============================================================================
//
// Defcon1 and Defcon3 are the security council's emergency levers: they signal the
// bridge to activate its safe harbour address. Both updates require the
// `StrataSecurityCouncil` role — these tests guard both directions of that
// invariant. Defcon1 bypasses the confirmation queue and applies in the same block
// as submission; Defcon3 follows the configured confirmation depth.

/// The bridge safe harbour activates in the same block that the security council's Defcon1
/// update is submitted — Defcon1 has no confirmation delay by definition.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon1_propagates_to_bridge_immediately() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial = harness.bridge_state().unwrap();
    assert!(
        !initial.safe_harbour().is_activated(),
        "safe harbour should start deactivated"
    );
    assert_eq!(
        initial.safe_harbour().active_address(),
        None,
        "there should be no active address before activation"
    );
    let configured_address = initial.safe_harbour().address().clone();

    harness
        .submit_admin_action(&mut ctx, defcon1_update())
        .await
        .unwrap();

    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        0,
        "Defcon1 must bypass the queue and apply immediately",
    );
    let bridge = harness.bridge_state().unwrap();
    assert!(
        bridge.safe_harbour().is_activated(),
        "safe harbour should be activated by Defcon1"
    );
    assert_eq!(
        bridge.safe_harbour().active_address(),
        Some(&configured_address),
        "active address should be the configured safe harbour address"
    );
}

/// The bridge safe harbour activates after the security council's Defcon3 update is enacted.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon3_propagates_to_bridge() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial = harness.bridge_state().unwrap();
    assert!(
        !initial.safe_harbour().is_activated(),
        "safe harbour should start deactivated"
    );
    let configured_address = initial.safe_harbour().address().clone();

    submit_and_activate(&harness, &mut ctx, defcon3_update()).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(
        bridge.safe_harbour().is_activated(),
        "safe harbour should activate once Defcon3 enacts"
    );
    assert_eq!(
        bridge.safe_harbour().active_address(),
        Some(&configured_address),
        "active address should be the configured safe harbour address"
    );
}

/// A Defcon3 update remains queued — and the bridge stays in its pre-defcon state — until
/// the configured confirmation depth elapses. Defcon1's immediate-apply behavior is
/// covered by [`test_defcon1_propagates_to_bridge_immediately`].
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon3_does_not_apply_before_activation() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    harness
        .submit_admin_action(&mut ctx, defcon3_update())
        .await
        .unwrap();

    assert_eq!(
        harness.admin_state().unwrap().queued().len(),
        1,
        "Defcon3 should be queued, not applied immediately"
    );
    assert!(
        !harness
            .bridge_state()
            .unwrap()
            .safe_harbour()
            .is_activated(),
        "safe harbour must stay deactivated while defcon is still queued"
    );
}

/// Defcon1 signed by any role other than the security council is rejected: the bridge stays
/// in its pre-defcon state, no update is queued, and the security council's seqno does not
/// advance.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon1_signed_by_non_security_council_rejected() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;
    assert_only_required_role_can_send(&harness, &mut ctx, defcon1_update()).await;
    assert!(
        !harness
            .bridge_state()
            .unwrap()
            .safe_harbour()
            .is_activated(),
        "safe harbour must stay deactivated when Defcon1 is signed by the wrong role",
    );
}

/// Defcon3 signed by any role other than the security council is rejected — same guarantees
/// as the Defcon1 case.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon3_signed_by_non_security_council_rejected() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;
    assert_only_required_role_can_send(&harness, &mut ctx, defcon3_update()).await;
    assert!(
        !harness
            .bridge_state()
            .unwrap()
            .safe_harbour()
            .is_activated(),
        "safe harbour must stay deactivated when Defcon3 is signed by the wrong role",
    );
}

// ============================================================================
// Safe Harbour Address Rotation → Bridge Safe Harbour
// ============================================================================
//
// The strata administrator — *not* the security council — rotates the bridge's
// safe harbour destination address, so the council cannot both trigger a sweep
// (via Defcon) and pick where the funds land. Rotation never changes activation
// state; the bridge picks up the new address after the configured confirmation
// depth elapses.

/// The bridge adopts the new safe harbour address after the administrator's rotation is
/// enacted. Activation state must be preserved across the rotation — only Defcon signals
/// toggle activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_harbour_address_update_propagates_to_bridge() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial = harness.bridge_state().unwrap();
    let initial_address = initial.safe_harbour().address().clone();
    assert!(
        !initial.safe_harbour().is_activated(),
        "safe harbour should start deactivated"
    );

    let new_address: SafeHarbourAddress = ArbitraryGenerator::new().generate();
    assert_ne!(
        new_address, initial_address,
        "test setup: the new address must differ from the initial one"
    );

    submit_and_activate(
        &harness,
        &mut ctx,
        safe_harbour_address_update(new_address.clone()),
    )
    .await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(
        bridge.safe_harbour().address(),
        &new_address,
        "bridge should adopt the new safe harbour address"
    );
    assert!(
        !bridge.safe_harbour().is_activated(),
        "address rotation alone must not activate the safe harbour"
    );
}

/// Safe harbour address rotation signed by any role other than the strata administrator is
/// rejected — same role-segregation guarantee as the Defcon cases, but enforced against the
/// administrator instead of the security council.
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_harbour_address_update_signed_by_non_administrator_rejected() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;
    let initial_address = harness
        .bridge_state()
        .unwrap()
        .safe_harbour()
        .address()
        .clone();

    let new_address: SafeHarbourAddress = ArbitraryGenerator::new().generate();
    assert_ne!(
        new_address, initial_address,
        "test setup: the new address must differ from the initial one"
    );
    assert_only_required_role_can_send(
        &harness,
        &mut ctx,
        safe_harbour_address_update(new_address),
    )
    .await;

    assert_eq!(
        harness.bridge_state().unwrap().safe_harbour().address(),
        &initial_address,
        "safe harbour address must be unchanged when rotation is signed by the wrong role",
    );
}

/// Once the safe harbour is activated, the address is frozen so bridge nodes always observe
/// a single destination — a subsequent administrator rotation must be rejected and the
/// activated address must remain unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_harbour_address_update_after_activation_rejected() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    let initial = harness.bridge_state().unwrap();
    let activated_address = initial.safe_harbour().address().clone();
    assert!(
        !initial.safe_harbour().is_activated(),
        "safe harbour should start deactivated"
    );

    // Activate the safe harbour via Defcon1 (applies in the same block).
    harness
        .submit_admin_action(&mut ctx, defcon1_update())
        .await
        .unwrap();
    assert!(
        harness
            .bridge_state()
            .unwrap()
            .safe_harbour()
            .is_activated(),
        "Defcon1 should activate the safe harbour"
    );

    // Attempt to rotate the address after activation — the update propagates through the
    // admin queue and the confirmation delay elapses, but the bridge must reject the change.
    let new_address: SafeHarbourAddress = ArbitraryGenerator::new().generate();
    assert_ne!(
        new_address, activated_address,
        "test setup: the new address must differ from the activated one"
    );
    submit_and_activate(&harness, &mut ctx, safe_harbour_address_update(new_address)).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(
        bridge.safe_harbour().is_activated(),
        "safe harbour should remain activated"
    );
    assert_eq!(
        bridge.safe_harbour().address(),
        &activated_address,
        "the address must remain frozen after activation"
    );
    assert_eq!(
        bridge.safe_harbour().active_address(),
        Some(&activated_address),
        "the active address must remain the original activated address"
    );
}
