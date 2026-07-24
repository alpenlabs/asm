//! End-to-end spec activation flow at the worker level.
//!
//! Drives the exact choreography an ASM upgrade performs on-chain: the admin
//! enacts an ASM VK upgrade, and the worker discovers the activation from the
//! enacted update's log — deriving the activating version as the successor of
//! the newest scheduled one — recording it for the block after the enacting
//! one. Also exercises the reorg path: abandoning the enacting block rolls
//! the activation back until the new branch re-enacts it.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use bitcoind_async_client::traits::Reader;
use harness::{
    admin::{asm_stf_vk_update, submit_and_activate, DEFAULT_CONFIRMATION_DEPTH},
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_logs::AsmStfUpdate;
use strata_asm_params::SpecId;
use strata_asm_worker::SpecActivationStore;
use strata_predicate::{PredicateKey, PredicateTypeId};

/// Stands in for the upgraded proving artifact's VK. At worker level nothing
/// verifies proofs, so any distinct predicate will do.
fn post_upgrade_predicate() -> PredicateKey {
    PredicateKey::new(PredicateTypeId::Bip340Schnorr, vec![0x77; 32])
}

/// The full upgrade lifecycle: the admin enacts an ASM VK upgrade, and the
/// worker records the activation of V1 — the successor of genesis-active V0 —
/// for the block after the enacting one, carrying the enacted VK.
#[tokio::test(flavor = "multi_thread")]
async fn test_spec_upgrade_activation_lifecycle() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    assert!(
        harness.context.list_spec_activations().unwrap().is_empty(),
        "nothing must activate before the upgrade",
    );

    // Enact the ASM VK upgrade switching to the new artifact's key.
    submit_and_activate(
        &harness,
        &mut admin_ctx,
        asm_stf_vk_update(post_upgrade_predicate()),
    )
    .await;

    let activations = harness.context.list_spec_activations().unwrap();
    assert_eq!(activations.len(), 1, "exactly one activation expected");
    assert_eq!(activations[0].version, SpecId::V1);
    assert_eq!(
        activations[0].activation_height(),
        activations[0].enacting_height + 1,
        "the version's rules apply from the block after the enacting one",
    );
    assert_eq!(
        activations[0].new_predicate,
        post_upgrade_predicate(),
        "the record must carry the VK the upgrade enacted",
    );

    // The enacting block's manifest carries the AsmStfUpdate log the worker
    // discovered the activation from.
    let enacting_hash = harness
        .client
        .get_block_hash(activations[0].enacting_height as u64)
        .await
        .unwrap();
    let enacting_block = harness.commitment_of(enacting_hash).await.unwrap();
    let update = harness
        .get_logs_at(&enacting_block)
        .iter()
        .find_map(|log| log.try_into_log::<AsmStfUpdate>().ok())
        .expect("the enacting block's manifest must carry the AsmStfUpdate log");
    assert_eq!(update.new_predicate(), &post_upgrade_predicate());
}

/// Reorging out the upgrade rolls the activation back, and the new branch
/// re-enacts it once the resurrected update reaches its activation height
/// again.
///
/// The reorg invalidates the *submission* block, so the admin commit/reveal
/// txs are evicted to the mempool. The replacement block is mined empty; the
/// next mempool-including block re-mines the txs one height later, so the
/// update re-queues and re-enacts with everything shifted by one block.
#[tokio::test(flavor = "multi_thread")]
async fn test_reorg_rolls_back_and_rediscovers_activation() {
    let Setup {
        harness,
        admin: mut admin_ctx,
        ..
    } = AsmTestHarnessBuilder::default().build().await;

    submit_and_activate(
        &harness,
        &mut admin_ctx,
        asm_stf_vk_update(post_upgrade_predicate()),
    )
    .await;

    let activations = harness.context.list_spec_activations().unwrap();
    assert_eq!(activations.len(), 1, "activation recorded at enactment");
    let enacting_height = activations[0].enacting_height;
    let submission_height = enacting_height as u64 - DEFAULT_CONFIRMATION_DEPTH as u64;

    // Reorg out the submission block and everything above it, replacing it
    // with one empty block so the tip sits back at the submission height.
    let submission_hash = harness
        .client
        .get_block_hash(submission_height)
        .await
        .unwrap();
    harness.reorg(submission_hash, 1).await.unwrap();

    assert!(
        harness.context.list_spec_activations().unwrap().is_empty(),
        "activation enacted on the abandoned branch must be rolled back",
    );

    // Mine through re-submission (the evicted txs return from the mempool)
    // and the confirmation depth: the update re-enacts on the new branch, one
    // height above the original enactment.
    harness
        .mine_blocks(1 + DEFAULT_CONFIRMATION_DEPTH as usize)
        .await
        .unwrap();

    let activations = harness.context.list_spec_activations().unwrap();
    assert_eq!(
        activations.len(),
        1,
        "the re-mined update must re-enact on the new branch",
    );
    assert_eq!(activations[0].version, SpecId::V1);
    assert_eq!(
        activations[0].enacting_height,
        enacting_height + 1,
        "re-submission lands one block later, shifting enactment by one",
    );
    assert_eq!(activations[0].new_predicate, post_upgrade_predicate());
}
