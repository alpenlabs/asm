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
use strata_asm_bridge_types::OperatorSelection;
use strata_asm_common::Subprotocol;
use strata_asm_logs::ExportExtraDataUpdate;
use strata_asm_proto_bridge::{BridgeSubprotoV1, OperatorClaimUnlock};
use strata_asm_proto_bridge_txs::BRIDGE_SUBPROTOCOL_ID;

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
            BridgeSubprotoV1::ID,
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
            .find_export_entry(BRIDGE_SUBPROTOCOL_ID, &expected_leaf)
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
        .find(|c| c.container_id() == BRIDGE_SUBPROTOCOL_ID)
        .expect("bridge export container should be present in the Moho state");
    assert_eq!(
        bridge_container.entries_mmr().num_entries(),
        1,
        "the fulfillment should append exactly one export-entry leaf",
    );
}

/// Reorg counterpart to [`test_withdrawal_fulfillment_creates_moho_export_entry`]:
/// if the block that fulfilled the withdrawal is reorged out and the replacement
/// (larger) chain does not re-include the fulfillment, the derived Moho state
/// carries no `OperatorClaimUnlock` for that deposit.
///
/// Flow:
/// 1. Deposit → assignment → fulfillment, exactly as the non-reorg test, and confirm the Moho state
///    gained the `OperatorClaimUnlock` leaf.
/// 2. Invalidate the fulfillment block and mine a strictly longer branch of empty blocks (which
///    excludes the resurrected fulfillment tx).
/// 3. Assert the fulfillment is undone: the assignment is live again, the export-entry store no
///    longer resolves the leaf, and the latest Moho state's bridge container MMR has zero leaves.
#[tokio::test(flavor = "multi_thread")]
async fn test_reorg_drops_moho_export_entry_when_fulfillment_excluded() {
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

    // 1. Deposit → assignment → fulfillment, as in the non-reorg test.
    harness.submit_deposits(&ctx, 1).await.unwrap();

    let pinned_operator = 1u32;
    harness
        .submit_checkpoint_with_withdrawal_intents(
            &mut checkpoint_harness,
            &[(denomination, OperatorSelection::specific(pinned_operator))],
        )
        .await
        .unwrap();

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

    let fulfillment_block = submit_withdrawal_fulfillment_tx(&harness, deposit_idx)
        .await
        .unwrap();

    // Precondition: the fulfillment mirrored the OperatorClaimUnlock leaf, so the
    // reorg below has something to drop.
    let leaf = OperatorClaimUnlock::new(deposit_idx, assignee).compute_hash();
    assert!(
        harness
            .moho_context
            .find_export_entry(BRIDGE_SUBPROTOCOL_ID, &leaf)
            .is_some(),
        "fulfillment should have mirrored the OperatorClaimUnlock leaf before the reorg",
    );

    // 2. Reorg the fulfillment block out under a strictly longer, fulfillment-free branch: three
    //    empty blocks replace the single dropped one, so the new tip out-heights the old chain and
    //    both workers re-anchor onto it.
    harness.reorg(fulfillment_block, 3).await.unwrap();

    // 3a. The reorg genuinely undid the fulfillment at the ASM level: deposit 0's
    //     assignment is live again on the replacement branch (the checkpoint that
    //     created it sits below the fork point, so it survives).
    assert!(
        harness
            .bridge_state()
            .unwrap()
            .assignments()
            .get_assignment(deposit_idx)
            .is_some(),
        "the assignment should be restored once its fulfillment is reorged out",
    );

    // 3b. The mirrored leaf is pruned when the fork point is re-derived forward
    //     over the branch that never fulfilled the withdrawal.
    assert!(
        harness
            .moho_context
            .find_export_entry(BRIDGE_SUBPROTOCOL_ID, &leaf)
            .is_none(),
        "reorg dropping the fulfillment must prune the OperatorClaimUnlock leaf",
    );

    // 3c. The latest Moho state is the new tip's, and its bridge export container
    //     carries no leaves — the accumulated-pow update maintains the container
    //     every block but never appends an export entry.
    let (_, moho_state) = harness
        .get_latest_moho_state()
        .unwrap()
        .expect("Moho state available after reorg");
    let bridge_container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_SUBPROTOCOL_ID)
        .expect("bridge export container should be present in the Moho state");
    assert_eq!(
        bridge_container.entries_mmr().num_entries(),
        0,
        "the reorged-out fulfillment must leave the bridge export MMR empty",
    );
}
