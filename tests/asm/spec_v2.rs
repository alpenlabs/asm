//! Spec 2 takes over the admin confirmation depths when it activates.
#![allow(
    unused_crate_dependencies,
    reason = "dependencies shared across integration tests"
)]

use integration_tests::harness::{
    admin::{
        asm_stf_vk_update, sequencer_update, uniform_confirmation_depths, AdminExt,
        DEFAULT_CONFIRMATION_DEPTH,
    },
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use strata_asm_admin_types::UpdateTxType;
use strata_asm_common::AsmSpec;
use strata_asm_spec::{StrataAsmSpec, StrataAsmSpecV2};
use strata_asm_worker::ExecutionRegistry;
use strata_predicate::PredicateKey;

/// Longer than the genesis depth, so an update re-timed to it would visibly miss its slot.
const SPEC_V2_CONFIRMATION_DEPTH: u16 = 5;
const _: () = assert!(SPEC_V2_CONFIRMATION_DEPTH > DEFAULT_CONFIRMATION_DEPTH);

fn execution_registry() -> ExecutionRegistry {
    let mut registry = ExecutionRegistry::default();
    registry
        .register(PredicateKey::always_accept(), StrataAsmSpec)
        .unwrap();
    // This harness tests native execution authority, not receipt verification.
    registry
        .register(
            PredicateKey::never_accept(),
            StrataAsmSpecV2::new(Some(uniform_confirmation_depths(
                SPEC_V2_CONFIRMATION_DEPTH,
            ))),
        )
        .unwrap();
    registry
}

#[tokio::test(flavor = "multi_thread")]
async fn spec_v2_queues_later_updates_with_its_depths_and_keeps_earlier_ones_on_time() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_execution_registry(execution_registry)
        .build()
        .await;

    // Queue the upgrade, then one more update in the next block, both under spec 0.
    harness
        .submit_admin_action(
            &mut admin_ctx,
            asm_stf_vk_update(PredicateKey::never_accept()),
        )
        .await
        .unwrap();
    harness
        .submit_admin_action(&mut admin_ctx, sequencer_update([7u8; 32]))
        .await
        .unwrap();
    let (_, state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(state.spec_id, StrataAsmSpec::ID);
    let in_flight = harness.admin_state().unwrap().queued()[1].clone();

    // The upgrade enacts at the end of the next block, which spec 0 still executes.
    harness.mine_block(None).await.unwrap();
    let (_, enacting) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(
        enacting.spec_id,
        StrataAsmSpec::ID,
        "old spec executes the enacting block"
    );

    // The next block runs under spec 2, which is also where the in-flight update was due.
    harness.mine_block(None).await.unwrap();
    let (first_v2, state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(state.spec_id, StrataAsmSpecV2::ID);
    assert_eq!(
        in_flight.activation_height(),
        first_v2.height(),
        "the update queued under spec 0 was due in the first spec 2 block"
    );
    let admin = harness.admin_state().unwrap();
    assert!(
        admin.queued().is_empty(),
        "the update queued under spec 0 enacts at its original height"
    );
    assert_eq!(
        admin.confirmation_depth(UpdateTxType::SequencerUpdate),
        Some(SPEC_V2_CONFIRMATION_DEPTH)
    );

    // An update submitted under spec 2 waits for spec 2's depth.
    harness
        .submit_admin_action(&mut admin_ctx, sequencer_update([7u8; 32]))
        .await
        .unwrap();
    let (submitted, _) = harness.get_latest_asm_state().unwrap().unwrap();
    let admin = harness.admin_state().unwrap();
    let [queued] = admin.queued() else {
        panic!("expected one queued update, found {:?}", admin.queued());
    };
    assert_eq!(
        queued.activation_height(),
        submitted.height() + u32::from(SPEC_V2_CONFIRMATION_DEPTH)
    );
}
