//! Admin → EE STF interaction tests
//!
//! Tests the propagation of EE predicate updates as `EePredicateKeyUpdate`
//! logs in the manifest, authorized by the `AlpenAdministrator` role.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{create_test_admin_setup, predicate_update, AdminExt},
    test_harness::AsmTestHarnessBuilder,
};
use integration_tests::harness;
use strata_asm_logs::EePredicateKeyUpdate;
use strata_asm_proto_admin_txs::actions::updates::predicate::ProofType;
use strata_identifiers::AccountSerial;
use strata_predicate::PredicateKey;

/// Verifies EE predicate updates emit an `EePredicateKeyUpdate` log in the
/// manifest after activation, authorized via the `AlpenAdministrator` role.
///
/// Flow:
/// 1. Submit predicate update with `ProofType::EeStf` (gets queued under `AlpenAdministrator`)
/// 2. Mine blocks to trigger activation (confirmation_depth=2)
/// 3. Verify the manifest contains an `EePredicateKeyUpdate` log with the correct predicate and
///    account serial
#[tokio::test(flavor = "multi_thread")]
async fn test_ee_predicate_update_emits_log() {
    let (admin_config, mut ctx) = create_test_admin_setup(2);
    let harness = AsmTestHarnessBuilder::default()
        .with_admin_config(admin_config)
        .build()
        .await
        .unwrap();

    // Initialize subprotocols (genesis state has no sections).
    harness.mine_block(None).await.unwrap();

    // Submit an EE predicate update (gets queued for AlpenAdministrator role).
    let new_predicate = PredicateKey::always_accept();
    harness
        .submit_admin_action(
            &mut ctx,
            predicate_update(new_predicate.clone(), ProofType::EeStf),
        )
        .await
        .unwrap();

    // Verify it's queued, not applied yet.
    let state = harness.admin_state().unwrap();
    assert_eq!(state.queued().len(), 1, "Predicate update should be queued");

    // Mine blocks to trigger activation (confirmation_depth=2).
    harness.mine_block(None).await.unwrap();
    harness.mine_block(None).await.unwrap();

    // Admin queue should be empty.
    let final_state = harness.admin_state().unwrap();
    assert_eq!(
        final_state.queued().len(),
        0,
        "Queue should be empty after activation"
    );

    // Find the EePredicateKeyUpdate log in the stored manifests.
    let manifests = harness.get_stored_manifests();
    let ee_update = manifests
        .iter()
        .flat_map(|m| &m.logs)
        .find_map(|log| log.try_into_log::<EePredicateKeyUpdate>().ok())
        .expect("expected an EePredicateKeyUpdate log in manifests");

    assert_eq!(
        ee_update.new_predicate(),
        &new_predicate,
        "EePredicateKeyUpdate log should contain the new predicate"
    );
    assert_eq!(
        ee_update.account(),
        AccountSerial::one(),
        "EePredicateKeyUpdate log should target the EE account at serial one"
    );
}
