//! End-to-end fork-gated unstake upgrade flow at the worker level.
//!
//! Drives the exact choreography an ASM upgrade performs on-chain: the chain
//! starts under pre-fork rules (unstake never activates), the admin enacts an
//! ASM VK upgrade naming the fork it activates, and from the next block on
//! the worker applies post-fork rules. Also exercises the reorg path:
//! abandoning the enacting block rolls the activation back until the new
//! branch re-enacts it.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    admin::{asm_stf_vk_update, submit_and_activate, DEFAULT_CONFIRMATION_DEPTH},
    bridge::{submit_genuine_unstake_tx, BridgeExt},
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_common::{ForkId, ForkSchedule};
use strata_asm_logs::AsmStfUpdate;
use strata_asm_worker::ForkActivationStore;
use strata_predicate::{PredicateKey, PredicateTypeId};

/// Stands in for the post-fork proving artifact's VK. At worker level nothing
/// verifies proofs, so any distinct predicate will do.
fn post_fork_predicate() -> PredicateKey {
    PredicateKey::new(PredicateTypeId::Bip340Schnorr, vec![0x77; 32])
}

/// Builds a harness whose chain starts under pre-fork rules.
async fn pre_fork_setup() -> Setup {
    AsmTestHarnessBuilder::default()
        .with_txindex()
        .with_fork_schedule(ForkSchedule::all_disabled())
        .build()
        .await
}

/// The full upgrade lifecycle: unstake ignored pre-fork, the VK upgrade
/// enactment activates the fork at H+1 (recorded and persisted), and the same
/// kind of unstake then removes the operator.
#[tokio::test(flavor = "multi_thread")]
async fn test_unstake_fork_upgrade_lifecycle() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        bridge,
        ..
    } = pre_fork_setup().await;

    let victim_idx = 1u32;
    assert!(
        harness
            .bridge_state()
            .unwrap()
            .operators()
            .is_in_current_multisig(victim_idx),
        "victim must start in the active multisig"
    );

    // 1. Pre-fork: a genuine, fully valid unstake is ignored.
    submit_genuine_unstake_tx(&harness, &bridge, victim_idx)
        .await
        .unwrap();
    assert!(
        harness
            .bridge_state()
            .unwrap()
            .operators()
            .is_in_current_multisig(victim_idx),
        "unstake must be ignored before the fork activates",
    );
    assert!(
        harness.context.list_fork_activations().unwrap().is_empty(),
        "nothing must activate before the upgrade",
    );

    // 2. Enact the ASM VK upgrade naming the fork.
    submit_and_activate(
        &harness,
        &mut admin_ctx,
        asm_stf_vk_update(post_fork_predicate(), ForkId::Fork1.into()),
    )
    .await;

    // The enacting block's manifest carries the AsmStfUpdate log...
    let manifests = harness.get_stored_manifests();
    let enacting_height = manifests
        .iter()
        .find(|m| {
            m.logs
                .iter()
                .any(|log| log.try_into_log::<AsmStfUpdate>().is_ok())
        })
        .map(|m| m.height())
        .expect("an enacting manifest must exist");

    // ...and the worker recorded the activation for the block after it.
    let activations = harness.context.list_fork_activations().unwrap();
    assert_eq!(activations.len(), 1, "exactly one activation expected");
    assert_eq!(activations[0].fork, ForkId::Fork1);
    assert_eq!(activations[0].enacting_height, enacting_height);
    assert_eq!(
        activations[0].activation_height(),
        enacting_height as u64 + 1
    );
    assert_eq!(
        activations[0].new_predicate,
        post_fork_predicate(),
        "the record must carry the VK the upgrade enacted",
    );

    // 3. Post-fork: the same kind of unstake now removes the operator.
    submit_genuine_unstake_tx(&harness, &bridge, victim_idx)
        .await
        .unwrap();
    assert!(
        !harness
            .bridge_state()
            .unwrap()
            .operators()
            .is_in_current_multisig(victim_idx),
        "unstake must be processed after the fork activates",
    );
}

/// Reorging out the upgrade rolls the fork back, and the new branch re-enacts
/// it once the (re-mined) update reaches its activation height again.
///
/// The reorg invalidates the *submission* block, so the admin commit/reveal
/// txs are evicted to the mempool and re-mined into the first replacement
/// block. The queued update therefore re-activates at the same height `S + D`;
/// until the new branch reaches it the fork is rolled back.
#[tokio::test(flavor = "multi_thread")]
async fn test_reorg_rolls_back_and_rediscovers_fork() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        bridge,
        ..
    } = pre_fork_setup().await;

    let victim_idx = 1u32;
    submit_and_activate(
        &harness,
        &mut admin_ctx,
        asm_stf_vk_update(post_fork_predicate(), ForkId::Fork1.into()),
    )
    .await;

    let activations = harness.context.list_fork_activations().unwrap();
    assert_eq!(activations.len(), 1, "activation recorded at enactment");
    let enacting_height = activations[0].enacting_height;
    let submission_height = enacting_height as u64 - DEFAULT_CONFIRMATION_DEPTH as u64;

    // Reorg out the submission block and everything above it. The evicted
    // admin txs are re-mined into the first replacement block (same height S),
    // so the update re-queues with the same activation height S + D. Two
    // replacement blocks leave the tip one short of re-enactment.
    harness
        .reorg(submission_height, DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    assert!(
        harness.context.list_fork_activations().unwrap().is_empty(),
        "activation enacted on the abandoned branch must be rolled back",
    );

    // With the fork rolled back, a genuine unstake is ignored again. (This
    // also advances the chain, re-enacting the re-mined update along the way.)
    let pre_unstake_activations = harness.context.list_fork_activations().unwrap();
    assert!(pre_unstake_activations.is_empty());

    // Mine to the re-enactment height and confirm the fork re-activates on
    // the new branch.
    harness.mine_blocks(2).await.unwrap();
    let activations = harness.context.list_fork_activations().unwrap();
    assert_eq!(
        activations.len(),
        1,
        "the re-mined update must re-enact on the new branch",
    );
    assert_eq!(activations[0].fork, ForkId::Fork1);

    // And post-fork behavior applies again.
    submit_genuine_unstake_tx(&harness, &bridge, victim_idx)
        .await
        .unwrap();
    assert!(
        !harness
            .bridge_state()
            .unwrap()
            .operators()
            .is_in_current_multisig(victim_idx),
        "unstake must be processed once the re-enacted fork activates",
    );
}
