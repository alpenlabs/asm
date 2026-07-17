//! Bridge integration tests

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use harness::{
    bridge::{
        submit_attacker_keyed_unstake_tx, submit_forged_unstake_tx,
        submit_withdrawal_fulfillment_tx, BridgeExt,
    },
    checkpoint::CheckpointExt,
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_common::Subprotocol;
use strata_asm_logs::ExportExtraDataUpdate;
use strata_asm_proto_bridge_v1::{BridgeV1Subproto, OperatorClaimUnlock};
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_proto_bridge_v1_types::OperatorSelection;

/// Regression: a forged unstake transaction must NOT remove an operator.
///
/// The exploit spends an attacker-funded P2WSH UTXO whose witnessScript is
/// `OP_DROP OP_DROP OP_DROP OP_TRUE`. Bitcoin accepts the spend because the
/// witnessScript executes to true. ASM's unstake parser sees a canonical
/// `stake_connector_script` bound to a known historical N/N pubkey at
/// `witness[2]`, so the *parse* still succeeds. The fix in
/// `validate_unstake_info` rejects the transaction at the handler level by
/// comparing the prevout's `scriptPubKey` against the canonical
/// stake-connector commitment, which the attacker's P2WSH UTXO cannot match.
#[tokio::test(flavor = "multi_thread")]
async fn test_forged_unstake_does_not_remove_operator() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;

    let initial_state = harness.bridge_state().unwrap();
    let victim_idx = 1u32;
    assert!(
        initial_state.operators().is_in_current_multisig(victim_idx),
        "victim must start in the active multisig"
    );
    let initial_agg_key = *initial_state.operators().agg_key();

    submit_forged_unstake_tx(&harness, victim_idx)
        .await
        .expect("exploit tx should be accepted by Bitcoin");

    // After the fix, ASM must reject the forged unstake and leave the active
    // multisig untouched.
    let post_state = harness.bridge_state().unwrap();
    assert!(
        post_state.operators().is_in_current_multisig(victim_idx),
        "forged unstake removed an operator without N/N authorization",
    );
    assert_eq!(
        *post_state.operators().agg_key(),
        initial_agg_key,
        "agg key must remain unchanged when no real unstake happened",
    );
}

/// Regression: an unstake that spends a *genuine but attacker-keyed* stake connector must NOT
/// remove an operator.
///
/// This closes the residual bypass that the witness-layout fix alone left open. The attacker
/// mints `P2TR(NUMS, stake_connector_script(stake_hash, attacker_key))`, funds it, and spends it
/// with a real Schnorr signature for `attacker_key`. Both checks an attacker can satisfy on their
/// own hold here — the prevout *is* a canonical stake connector, and Bitcoin *did* authorize the
/// spend via `OP_CHECKSIGVERIFY`. Only the binding that `attacker_key` was a historical N/N
/// aggregated key of the operator set rejects it, which it must.
#[tokio::test(flavor = "multi_thread")]
async fn test_attacker_keyed_unstake_does_not_remove_operator() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;

    let initial_state = harness.bridge_state().unwrap();
    let victim_idx = 1u32;
    assert!(
        initial_state.operators().is_in_current_multisig(victim_idx),
        "victim must start in the active multisig"
    );
    let initial_agg_key = *initial_state.operators().agg_key();

    submit_attacker_keyed_unstake_tx(&harness, victim_idx)
        .await
        .expect("exploit tx should be accepted by Bitcoin");

    // ASM must reject the attacker-keyed unstake and leave the active multisig untouched.
    let post_state = harness.bridge_state().unwrap();
    assert!(
        post_state.operators().is_in_current_multisig(victim_idx),
        "attacker-keyed unstake removed an operator without N/N authorization",
    );
    assert_eq!(
        *post_state.operators().agg_key(),
        initial_agg_key,
        "agg key must remain unchanged when no real unstake happened",
    );
}

/// Every L1 block, the bridge must publish the verified accumulated proof of work as its export
/// container's `extra_data`. With no other transactions, that update is the *only* log the STF
/// emits, it is keyed by the bridge container id, and its value strictly increases as each new
/// block adds work.
#[tokio::test(flavor = "multi_thread")]
async fn test_bridge_publishes_increasing_accumulated_pow() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;

    let mut last_pow: Option<[u8; 32]> = None;
    for _ in 0..4 {
        harness.mine_block(None).await.unwrap();

        let (block, _) = harness
            .get_latest_asm_state()
            .unwrap()
            .expect("ASM state available");

        // An empty block emits exactly one log: the bridge's accumulated-pow update.
        let logs = harness.get_logs_at(&block);
        assert_eq!(logs.len(), 1, "expected exactly one emitted log per block");
        let update = logs[0]
            .try_into_log::<ExportExtraDataUpdate>()
            .expect("the emitted log must be an ExportExtraDataUpdate");
        assert_eq!(
            update.container_id(),
            BridgeV1Subproto::ID,
            "accumulated pow must be published under the bridge container id"
        );

        // The accumulated work is stored little-endian; reverse to big-endian so the byte arrays
        // compare as the numbers they encode. Each new block adds work, so it must increase.
        let pow = *update.extra_data();
        if let Some(prev) = last_pow {
            let (mut pow_be, mut prev_be) = (pow, prev);
            pow_be.reverse();
            prev_be.reverse();
            assert!(pow_be > prev_be, "accumulated pow must increase each block");
        }
        last_pow = Some(pow);
    }
}

/// End-to-end: fulfilling a withdrawal makes the Moho worker mirror an
/// `OperatorClaimUnlock` export entry for the assigned operator and deposit.
///
/// When the bridge processes a withdrawal fulfillment it emits a
/// `NewExportEntry` log whose leaf is the hash of `OperatorClaimUnlock { deposit_idx, operator_idx
/// }`, under the bridge container. The Moho worker folds that log into the bridge
/// container's `ExportState` MMR and mirrors the leaf into its export-entry
/// store (which the runner rebuilds inclusion proofs from). This drives the full
/// deposit → assignment → fulfillment chain and asserts the derived Moho state
/// carries exactly that entry.
///
/// Flow:
/// 1. Submit one deposit (index 0).
/// 2. Submit a checkpoint whose withdrawal pins operator 1, creating the assignment.
/// 3. Fulfill the withdrawal for deposit 0.
/// 4. Assert the Moho export-entry store resolves the `OperatorClaimUnlock` hash, and the latest
///    Moho state's bridge container MMR gained exactly that one leaf.
#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_fulfillment_creates_moho_export_entry() {
    let Setup {
        harness,
        bridge: ctx,
        checkpoint: mut checkpoint_harness,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;
    let denomination = ctx.denomination().to_sat();

    // 1. One deposit to assign against.
    harness.submit_deposits(&ctx, 1).await.unwrap();

    // 2. A withdrawal pinned to operator 1 so the assignee is deterministic.
    let pinned_operator = 1u32;
    harness
        .submit_checkpoint_with_withdrawal_intents(
            &mut checkpoint_harness,
            &[(denomination, OperatorSelection::specific(pinned_operator))],
        )
        .await
        .unwrap();

    // Capture the assignment (removed once fulfilled) to build the expected leaf.
    let deposit_idx = 0u32;
    let assignee = {
        let bridge_state = harness.bridge_state().unwrap();
        let assignment = bridge_state
            .assignments()
            .get_assignment(deposit_idx)
            .expect("assignment for deposit 0 should exist");
        assert_eq!(assignment.current_assignee(), pinned_operator);
        assignment.current_assignee()
    };

    // 3. Fulfill the withdrawal.
    submit_withdrawal_fulfillment_tx(&harness, deposit_idx)
        .await
        .unwrap();

    // The assignment is consumed on fulfillment.
    assert!(
        harness
            .bridge_state()
            .unwrap()
            .assignments()
            .get_assignment(deposit_idx)
            .is_none(),
        "assignment should be removed after fulfillment"
    );

    // 4a. The Moho worker mirrored the export-entry leaf: the hash of the
    //     operator's claim on this deposit resolves in its export-entry store.
    let expected_leaf = OperatorClaimUnlock::new(deposit_idx, assignee).compute_hash();
    assert!(
        harness
            .moho_context
            .find_export_entry(BRIDGE_V1_SUBPROTOCOL_ID, &expected_leaf)
            .is_some(),
        "Moho export-entry store should resolve the OperatorClaimUnlock leaf",
    );

    // 4b. The same leaf lives in the committed Moho state: the bridge container's
    //     export MMR gained exactly one leaf (accumulated-pow updates only touch
    //     the container's extra data, never its leaves).
    let (_, moho_state) = harness
        .get_latest_moho_state()
        .unwrap()
        .expect("Moho state available after fulfillment");
    let bridge_container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
        .expect("bridge export container should be present in the Moho state");
    assert_eq!(
        bridge_container.entries_mmr().num_entries(),
        1,
        "the fulfillment should append exactly one export-entry leaf",
    );
}
