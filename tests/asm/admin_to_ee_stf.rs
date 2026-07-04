//! Admin → EE STF interaction tests
//!
//! Tests the propagation of EE predicate updates as `EePredicateKeyUpdate`
//! logs in the manifest, authorized by the `AlpenAdministrator` role.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{ee_stf_vk_update, AdminExt, DEFAULT_CONFIRMATION_DEPTH},
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_logs::EePredicateKeyUpdate;
use strata_identifiers::{AccountSerial, SYSTEM_RESERVED_ACCTS};
use strata_predicate::PredicateKey;

/// Verifies EE predicate updates emit an `EePredicateKeyUpdate` log in the
/// manifest after activation, authorized via the `AlpenAdministrator` role.
///
/// Flow:
/// 1. Submit EE STF verifying-key update (gets queued under `AlpenAdministrator`)
/// 2. Mine blocks to trigger activation (confirmation_depth=2)
/// 3. Verify the manifest contains an `EePredicateKeyUpdate` log with the correct predicate and
///    account serial
#[tokio::test(flavor = "multi_thread")]
async fn test_ee_predicate_update_emits_log() {
    let Setup {
        harness,
        admin: mut ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    // Submit an EE predicate update (gets queued for AlpenAdministrator role).
    let new_predicate = PredicateKey::always_accept();
    harness
        .submit_admin_action(&mut ctx, ee_stf_vk_update(new_predicate.clone()))
        .await
        .unwrap();

    // Verify it's queued, not applied yet.
    let state = harness.admin_state().unwrap();
    assert_eq!(state.queued().len(), 1, "Predicate update should be queued");

    // Mine blocks to trigger activation.
    let activation_blocks = harness
        .mine_blocks(DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    // Admin queue should be empty.
    let final_state = harness.admin_state().unwrap();
    assert_eq!(
        final_state.queued().len(),
        0,
        "Queue should be empty after activation"
    );

    // The update log is emitted at whichever block activated it; search the
    // blocks we just mined rather than dumping every stored manifest.
    let ee_update = harness
        .find_log_in_blocks::<EePredicateKeyUpdate>(&activation_blocks)
        .await
        .unwrap()
        .expect("expected an EePredicateKeyUpdate log in the activation blocks");

    assert_eq!(
        ee_update.new_predicate(),
        &new_predicate,
        "EePredicateKeyUpdate log should contain the new predicate"
    );
    assert_eq!(
        ee_update.account(),
        AccountSerial::new(SYSTEM_RESERVED_ACCTS),
        "EePredicateKeyUpdate log should target the EE account at serial one"
    );
}
