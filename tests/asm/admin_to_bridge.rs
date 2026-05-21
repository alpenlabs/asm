//! Admin → Bridge subprotocol interaction tests
//!
//! Tests the propagation of operator set updates and defcon signals from the admin
//! subprotocol to the bridge subprotocol via interprotocol messaging.
//!
//! Key interactions tested:
//! - Operator additions → bridge operator table gains new members
//! - Operator removals → bridge operator table deactivates members
//! - Combined add/remove → both applied atomically after activation
//! - Defcon1/Defcon3 from the security council → bridge activates the safe harbour
//! - Defcon1/Defcon3 signed by any other role → rejected, bridge unchanged
//! - Safe harbour address rotation from the security council → bridge adopts new address
//! - Safe harbour address rotation signed by any other role → rejected, bridge unchanged

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use bitcoin_bosd::Descriptor;
use harness::{
    admin::{
        create_test_admin_setup, defcon1_update, defcon3_update, operator_set_update,
        safe_harbour_address_update, AdminContext, AdminExt,
    },
    bridge::{create_test_bridge_setup, BridgeExt},
    test_harness::{AsmTestHarness, AsmTestHarnessBuilder},
};
use integration_tests::harness;
use strata_asm_params::Role;
use strata_asm_proto_admin_txs::actions::MultisigAction;
use strata_asm_proto_bridge_v1_txs::test_utils::create_test_operators;
use strata_crypto::EvenPublicKey;

const CONFIRMATION_DEPTH: u16 = 2;
const NUM_INITIAL_OPERATORS: usize = 3;

/// Sets up an ASM harness with admin + bridge subprotocols and mines the init block.
async fn setup() -> (AsmTestHarness, AdminContext) {
    let (admin_config, admin_ctx) = create_test_admin_setup(CONFIRMATION_DEPTH);
    let (bridge_config, _) = create_test_bridge_setup(NUM_INITIAL_OPERATORS);

    let harness = AsmTestHarnessBuilder::default()
        .with_admin_config(admin_config)
        .with_bridge_config(bridge_config)
        .build()
        .await
        .unwrap();

    // Initialize subprotocols
    harness.mine_block(None).await.unwrap();

    (harness, admin_ctx)
}

/// Submits an operator set update and mines enough blocks to activate it.
async fn submit_and_activate(
    harness: &AsmTestHarness,
    ctx: &mut AdminContext,
    add: Vec<EvenPublicKey>,
    remove: Vec<u32>,
) {
    harness
        .submit_admin_action(ctx, operator_set_update(add, remove))
        .await
        .unwrap();

    // Mine `CONFIRMATION_DEPTH` blocks to trigger activation
    for _ in 0..CONFIRMATION_DEPTH {
        harness.mine_block(None).await.unwrap();
    }
}

// ============================================================================
// Operator Set Updates → Bridge Operator Table
// ============================================================================

/// Verifies that adding an operator via admin propagates to the bridge after activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_add_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial_bridge = harness.bridge_state().unwrap();
    assert_eq!(initial_bridge.operators().len(), 3);

    let (_, new_pubkeys) = create_test_operators(1);
    submit_and_activate(&harness, &mut ctx, vec![new_pubkeys[0]], vec![]).await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(bridge.operators().len(), 4);
    assert!(bridge.operators().is_in_current_multisig(3));
}

/// Verifies that removing an operator via admin propagates to the bridge after activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_remove_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial_agg_key = *harness.bridge_state().unwrap().operators().agg_key();

    submit_and_activate(&harness, &mut ctx, vec![], vec![0]).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(!bridge.operators().is_in_current_multisig(0));
    assert!(bridge.operators().is_in_current_multisig(1));
    assert!(bridge.operators().is_in_current_multisig(2));
    assert_ne!(*bridge.operators().agg_key(), initial_agg_key);
}

/// Verifies combined add and remove in a single operator set update.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_add_and_remove_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial_agg_key = *harness.bridge_state().unwrap().operators().agg_key();

    let (_, new_pubkeys) = create_test_operators(1);
    submit_and_activate(&harness, &mut ctx, vec![new_pubkeys[0]], vec![1]).await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(bridge.operators().len(), 4);
    assert!(bridge.operators().is_in_current_multisig(0));
    assert!(!bridge.operators().is_in_current_multisig(1));
    assert!(bridge.operators().is_in_current_multisig(2));
    assert!(bridge.operators().is_in_current_multisig(3));
    assert_ne!(*bridge.operators().agg_key(), initial_agg_key);
}

/// Verifies the update is queued and does not affect the bridge until activated.
#[tokio::test(flavor = "multi_thread")]
async fn test_operator_update_does_not_apply_before_activation() {
    let (harness, mut ctx) = setup().await;

    let (_, new_pubkeys) = create_test_operators(1);

    // Submit but do NOT mine enough blocks to activate
    harness
        .submit_admin_action(&mut ctx, operator_set_update(vec![new_pubkeys[0]], vec![]))
        .await
        .unwrap();

    let admin_state = harness.admin_state().unwrap();
    assert_eq!(admin_state.queued().len(), 1, "Update should be queued");

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(
        bridge.operators().len(),
        3,
        "Bridge should be unchanged while update is queued"
    );
}

// ============================================================================
// Defcon Signals → Bridge Safe Harbour
// ============================================================================
//
// Defcon1 and Defcon3 are the security council's emergency levers: they signal the
// bridge to activate its safe harbour address. Both updates require the
// `StrataSecurityCouncil` role — these tests guard both directions of that
// invariant.

/// The bridge safe harbour activates after the security council's Defcon1 update is enacted.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon1_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial = harness.bridge_state().unwrap();
    assert!(!initial.safe_harbour().is_activated());
    assert_eq!(initial.safe_harbour().active_address(), None);
    let configured_address = initial.safe_harbour().address().clone();

    submit_and_activate_action(&harness, &mut ctx, defcon1_update()).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(bridge.safe_harbour().is_activated());
    assert_eq!(
        bridge.safe_harbour().active_address(),
        Some(&configured_address),
    );
}

/// The bridge safe harbour activates after the security council's Defcon3 update is enacted.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon3_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial = harness.bridge_state().unwrap();
    assert!(!initial.safe_harbour().is_activated());
    let configured_address = initial.safe_harbour().address().clone();

    submit_and_activate_action(&harness, &mut ctx, defcon3_update()).await;

    let bridge = harness.bridge_state().unwrap();
    assert!(bridge.safe_harbour().is_activated());
    assert_eq!(
        bridge.safe_harbour().active_address(),
        Some(&configured_address),
    );
}

/// A defcon update remains queued — and the bridge stays in its pre-defcon state — until
/// the configured confirmation depth elapses.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon1_does_not_apply_before_activation() {
    let (harness, mut ctx) = setup().await;

    harness
        .submit_admin_action(&mut ctx, defcon1_update())
        .await
        .unwrap();

    let admin_state = harness.admin_state().unwrap();
    assert_eq!(
        admin_state.queued().len(),
        1,
        "Defcon1 should be queued, not applied immediately"
    );

    let bridge = harness.bridge_state().unwrap();
    assert!(
        !bridge.safe_harbour().is_activated(),
        "Safe harbour must stay deactivated while defcon is still queued"
    );
}

/// Defcon1 signed by any role other than the security council is rejected: the bridge stays
/// in its pre-defcon state, no update is queued, and the security council's seqno does not
/// advance.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon1_signed_by_non_security_council_rejected() {
    assert_only_security_council_can_send(defcon1_update()).await;
}

/// Defcon3 signed by any role other than the security council is rejected — same guarantees
/// as the Defcon1 case.
#[tokio::test(flavor = "multi_thread")]
async fn test_defcon3_signed_by_non_security_council_rejected() {
    assert_only_security_council_can_send(defcon3_update()).await;
}

// ============================================================================
// Safe Harbour Address Rotation → Bridge Safe Harbour
// ============================================================================
//
// The security council can rotate the bridge's safe harbour destination address
// without changing its activation state. The bridge picks up the new address
// after the configured confirmation depth elapses.

/// The bridge adopts the new safe harbour address after the security council's rotation is
/// enacted. Activation state must be preserved across the rotation — only Defcon signals
/// toggle activation.
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_harbour_address_update_propagates_to_bridge() {
    let (harness, mut ctx) = setup().await;

    let initial = harness.bridge_state().unwrap();
    let initial_address = initial.safe_harbour().address().clone();
    assert!(!initial.safe_harbour().is_activated());

    let new_address = Descriptor::new_p2wpkh(&[0xCD; 20]);
    assert_ne!(new_address, initial_address);

    submit_and_activate_action(
        &harness,
        &mut ctx,
        safe_harbour_address_update(new_address.clone()),
    )
    .await;

    let bridge = harness.bridge_state().unwrap();
    assert_eq!(bridge.safe_harbour().address(), &new_address);
    // Address rotation alone must not activate the safe harbour.
    assert!(!bridge.safe_harbour().is_activated());
}

/// Safe harbour address rotation signed by any role other than the security council is
/// rejected — same role-segregation guarantees as the Defcon cases.
#[tokio::test(flavor = "multi_thread")]
async fn test_safe_harbour_address_update_signed_by_non_security_council_rejected() {
    let new_address = Descriptor::new_p2wpkh(&[0xCD; 20]);
    assert_only_security_council_can_send(safe_harbour_address_update(new_address)).await;
}

/// Submits a single admin action and mines `CONFIRMATION_DEPTH` blocks so it activates.
async fn submit_and_activate_action(
    harness: &AsmTestHarness,
    ctx: &mut AdminContext,
    action: MultisigAction,
) {
    harness.submit_admin_action(ctx, action).await.unwrap();
    for _ in 0..CONFIRMATION_DEPTH {
        harness.mine_block(None).await.unwrap();
    }
}

/// Submits `action` once per non-`StrataSecurityCouncil` role with that role's signing keys
/// and asserts the handler rejects all of them.
///
/// The action's required role is `StrataSecurityCouncil`, so signing with any other role's
/// keys must fail signature verification — verified by checking that the bridge safe harbour
/// stays deactivated, nothing is queued, and the security council's seqno doesn't advance.
async fn assert_only_security_council_can_send(action: MultisigAction) {
    assert_eq!(
        action.required_role(),
        Role::StrataSecurityCouncil,
        "this helper only exercises actions whose required role is the security council",
    );

    let (harness, mut ctx) = setup().await;

    for signing_role in [
        Role::StrataAdministrator,
        Role::StrataSequencerManager,
        Role::AlpenAdministrator,
    ] {
        harness
            .submit_admin_action_as_role(&mut ctx, action.clone(), signing_role)
            .await
            .unwrap();
    }

    // No update should have been queued and the update id counter must not advance.
    let admin_state = harness.admin_state().unwrap();
    assert_eq!(
        admin_state.queued().len(),
        0,
        "no update should be queued when signed by the wrong role",
    );
    assert_eq!(
        admin_state.next_update_id(),
        0,
        "next_update_id must not advance for rejected txs",
    );
    // The security council's on-chain seqno must stay at 0 — the wrong-role payloads carry
    // valid seqnos but the signature fails to verify against the council's threshold config.
    assert_eq!(
        admin_state
            .authority(Role::StrataSecurityCouncil)
            .unwrap()
            .last_seqno(),
        0,
        "security council seqno must not advance for rejected txs",
    );

    // Mine through the activation window to confirm nothing latent applies later.
    for _ in 0..CONFIRMATION_DEPTH {
        harness.mine_block(None).await.unwrap();
    }
    let bridge = harness.bridge_state().unwrap();
    assert!(
        !bridge.safe_harbour().is_activated(),
        "safe harbour must stay deactivated when a security-council action is signed by the wrong role",
    );
}
