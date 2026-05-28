//! Bridge integration tests

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    bridge::{submit_forged_unstake_tx, BridgeExt},
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;

/// Demonstrates the unstake witness-layout bypass: ASM removes an operator
/// even though no N/N signature ever authorized the unstake.
///
/// The exploit transaction spends an attacker-funded P2WSH UTXO whose
/// witnessScript is `OP_DROP OP_DROP OP_DROP OP_TRUE`. Bitcoin accepts the
/// spend because the witnessScript executes to true. ASM's unstake parser
/// indexes `witness[2]` as if the input were a Tapscript spend, sees a
/// canonical `stake_connector_script` bound to a known historical N/N pubkey,
/// and removes the attacker-chosen `operator_idx`.
#[tokio::test(flavor = "multi_thread")]
async fn test_forged_unstake_removes_operator() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;

    let initial_state = harness.bridge_state().unwrap();
    let victim_idx = 1u32;
    assert!(
        initial_state.operators().is_in_current_multisig(victim_idx),
        "victim must start in the active multisig"
    );
    let initial_agg_key = *initial_state.operators().agg_key();

    submit_forged_unstake_tx(&harness, victim_idx)
        .await
        .expect("exploit tx should be accepted by Bitcoin and processed by ASM");

    let post_state = harness.bridge_state().unwrap();
    assert!(
        !post_state.operators().is_in_current_multisig(victim_idx),
        "victim was removed despite no N/N signature being checked",
    );
    assert_ne!(
        *post_state.operators().agg_key(),
        initial_agg_key,
        "agg key must change after a member is removed",
    );
}
