//! Bridge Subprotocol Implementation
//!
//! This module contains the core subprotocol implementation that integrates
//! with the Strata Anchor State Machine (ASM).

use std::marker::PhantomData;

use strata_asm_bridge_types::BridgeInitConfig;
use strata_asm_common::{
    AsmLogEntry, AuxRequestCollector, HeaderVerificationState, MsgRelayer, SectionStateVersion,
    Subprotocol, SubprotocolId, TxInputRef, VerifiedAuxData,
    logging::{debug, error, info, warn},
};
use strata_asm_logs::ExportExtraDataUpdate;
use strata_asm_proto_bridge_msgs::BridgeIncomingMsg;
use strata_asm_proto_bridge_state::{BridgeStateV1, BridgeStateV2};
use strata_asm_proto_bridge_txs::{BRIDGE_SUBPROTOCOL_ID, errors::Mismatch, parser::parse_tx};
use strata_identifiers::L1BlockCommitment;

use crate::{
    claim::{ClaimV0, ClaimV1, ClaimVersion},
    errors::WithdrawalAssignmentError,
    handler::{handle_parsed_tx, preprocess_parsed_tx},
};

/// Bridge subprotocol implementation, parameterized by the claim version it commits.
///
/// This struct implements the [`Subprotocol`] trait to integrate the bridge functionality
/// with the ASM. It handles Bitcoin deposit processing, operator management, and withdrawal
/// coordination.
///
/// Every released version shares this implementation and differs only in `C`, so use one of
/// the aliases below rather than naming `C` at a call site. The subprotocol ID and the section
/// schema are the same for all of them: the claim version moves the export leaf, not the state.
/// They store section schema 0; [`BridgeSubprotoV3`] is the version that stores schema 1.
#[derive(Debug)]
pub struct BridgeSubproto<C: ClaimVersion>(PhantomData<C>);

/// The released bridge subprotocol, committing [`OperatorClaimUnlockV0`] export leaves.
///
/// [`OperatorClaimUnlockV0`]: strata_asm_bridge_types::OperatorClaimUnlockV0
pub type BridgeSubprotoV1 = BridgeSubproto<ClaimV0>;

/// The successor bridge subprotocol, committing [`OperatorClaimUnlockV1`] export leaves.
///
/// Switching to it moves every subsequent leaf, so it is reached through a spec activation
/// rather than by changing what an already-released ruleset invokes.
///
/// [`OperatorClaimUnlockV1`]: strata_asm_bridge_types::OperatorClaimUnlockV1
pub type BridgeSubprotoV2 = BridgeSubproto<ClaimV1>;

/// The bridge subprotocol that records stranded assignments, committing
/// [`OperatorClaimUnlockV1`] export leaves like [`BridgeSubprotoV2`].
///
/// When no active operator from a deposit's notary set can take an expired assignment, the
/// released versions halt block processing. This version marks the assignment unassignable,
/// leaves it with its current assignee, and keeps processing. Recording that status needs
/// section schema 1 ([`BridgeStateV2`]), so it is a separate [`Subprotocol`] implementation
/// rather than another claim version; spec 2 invokes it after migrating the section.
///
/// [`OperatorClaimUnlockV1`]: strata_asm_bridge_types::OperatorClaimUnlockV1
#[derive(Debug)]
pub struct BridgeSubprotoV3;

/// What the reassignment pass does with an expired assignment that no active operator from its
/// notary set can take.
#[derive(Clone, Copy, Debug)]
enum StrandedAssignment {
    /// Fail the block. Schema 0 cannot record an unassignable assignment, so the released
    /// versions keep the behavior they shipped with.
    Halt,
    /// Leave the assignment marked unassignable and continue (schema 1).
    MarkUnassignable,
}

impl<C: ClaimVersion> Subprotocol for BridgeSubproto<C> {
    const ID: SubprotocolId = BRIDGE_SUBPROTOCOL_ID;
    // Shared by every claim version: the claim shape is an output, not part of the section.
    const STATE_VERSION: SectionStateVersion = 0;

    type State = BridgeStateV1;

    type InitConfig = BridgeInitConfig;

    type Msg = BridgeIncomingMsg;

    fn init(config: &Self::InitConfig) -> Self::State {
        BridgeStateV1::new(config)
    }

    /// Pre-processes transactions to collect auxiliary data requests.
    ///
    /// This function runs before the main transaction processing to identify and request
    /// any auxiliary data needed for verification.
    fn pre_process_txs(
        state: &Self::State,
        txs: &[TxInputRef<'_>],
        collector: &mut AuxRequestCollector,
    ) {
        pre_process_bridge_txs(state, txs, collector);
    }

    /// Processes transactions and reassigns expired assignments.
    ///
    /// The function follows a two-phase approach:
    /// 1. **Transaction processing**: Handles incoming bridge transactions
    /// 2. **Post-processing**: Reassigns any expired assignments to new operators
    ///
    /// The order is load-bearing. The reassignment pass counts an assignment as expired once the
    /// current height reaches its deadline, so running it first would rotate the assignment away
    /// from an operator whose fulfillment confirms in that very block. Processing transactions
    /// first makes the deadline height fulfillable: the fulfillment removes the assignment, and
    /// the pass never sees it. An operator therefore gets the full window its deadline promises,
    /// and cannot lose the claim to a race it has no way to win.
    ///
    /// # Panics
    ///
    /// **CRITICAL**: This function panics if expired assignment reassignment fails, as this
    /// indicates a violation of the bridge's 1/N honesty assumption. The bridge protocol assumes at
    /// least one honest operator remains active to fulfill withdrawals. Failure to reassign
    /// expired assignments means no honest operators are available, representing an
    /// unrecoverable protocol breach that poses significant risk of fund loss.
    fn process_txs(
        state: &mut Self::State,
        txs: &[TxInputRef<'_>],
        header_vs: &HeaderVerificationState,
        verified_aux_data: &VerifiedAuxData,
        relayer: &mut impl MsgRelayer,
    ) {
        process_bridge_txs::<C>(
            state,
            txs,
            header_vs,
            verified_aux_data,
            relayer,
            StrandedAssignment::Halt,
        );
    }

    /// Processes incoming bridge messages
    ///
    /// This function handles messages sent to the bridge subprotocol. Currently processes:
    ///
    /// - **`DispatchWithdrawal`**: Creates withdrawal assignments by selecting available operators
    ///   to fulfill pending withdrawals. The assignment process ensures proper operator selection
    ///   based on availability, stake, and previous failure history.
    ///
    /// # Panics
    ///
    /// **CRITICAL**: This function panics if withdrawal assignment creation fails, as this
    /// indicates one of two catastrophic system failures:
    ///
    /// 1. **1/N Honest Assumption Violated**: No honest operators remain active, breaking the
    ///    fundamental security assumption of the bridge protocol
    /// 2. **Peg Mechanism Failure**: The bridge's peg to Bitcoin has been compromised, potentially
    ///    due to operator collusion or critical implementation bugs
    ///
    /// Both conditions represent unrecoverable protocol violations where continued operation
    /// poses significant risk of fund loss.
    fn process_msgs(state: &mut Self::State, msgs: &[Self::Msg], l1ref: &L1BlockCommitment) {
        process_bridge_msgs(state, msgs, l1ref);
    }
}

impl Subprotocol for BridgeSubprotoV3 {
    const ID: SubprotocolId = BRIDGE_SUBPROTOCOL_ID;
    // Schema 1 records each assignment's status; schema-0 sections are migrated by
    // `migrate_bridge_section` in spec 2's `prepare`.
    const STATE_VERSION: SectionStateVersion = 1;

    type State = BridgeStateV2;

    type InitConfig = BridgeInitConfig;

    type Msg = BridgeIncomingMsg;

    fn init(config: &Self::InitConfig) -> Self::State {
        BridgeStateV2::from(BridgeStateV1::new(config))
    }

    /// Pre-processes transactions exactly as [`BridgeSubproto`] does.
    fn pre_process_txs(
        state: &Self::State,
        txs: &[TxInputRef<'_>],
        collector: &mut AuxRequestCollector,
    ) {
        pre_process_bridge_txs(state, txs, collector);
    }

    /// Processes transactions and reassigns expired assignments, in the order and with the
    /// deadline semantics of [`BridgeSubproto`].
    ///
    /// An expired assignment with no active operator from its historical notary set is marked
    /// unassignable instead of failing the block. It keeps its assignee, who may still fulfill
    /// it, and later passes skip it.
    ///
    /// # Panics
    ///
    /// Panics if reassignment encounters malformed assignment state.
    fn process_txs(
        state: &mut Self::State,
        txs: &[TxInputRef<'_>],
        header_vs: &HeaderVerificationState,
        verified_aux_data: &VerifiedAuxData,
        relayer: &mut impl MsgRelayer,
    ) {
        process_bridge_txs::<ClaimV1>(
            state,
            txs,
            header_vs,
            verified_aux_data,
            relayer,
            StrandedAssignment::MarkUnassignable,
        );
    }

    /// Processes incoming bridge messages exactly as [`BridgeSubproto`] does.
    ///
    /// # Panics
    ///
    /// Panics if withdrawal assignment creation fails; see [`BridgeSubproto`].
    fn process_msgs(state: &mut Self::State, msgs: &[Self::Msg], l1ref: &L1BlockCommitment) {
        process_bridge_msgs(state, msgs, l1ref);
    }
}

/// Collects the auxiliary data requests of every bridge transaction in `txs`.
fn pre_process_bridge_txs(
    state: &BridgeStateV1,
    txs: &[TxInputRef<'_>],
    collector: &mut AuxRequestCollector,
) {
    // Pre-Process each transaction
    for tx in txs {
        // Parse transaction to extract structured data, then handle the preprocess transaction
        // to get the auxiliary requests. Transactions that are not directly processed by the
        // bridge subprotocol (e.g. `DepositRequest`, `Commit`) or are otherwise unparseable
        // are silently skipped.
        if let Some(parsed_tx) = parse_tx(tx) {
            preprocess_parsed_tx(parsed_tx, state, collector);
        }
    }
}

/// Handles every bridge transaction in `txs`, then reassigns expired assignments, treating
/// stranded ones as `stranded` directs.
///
/// # Panics
///
/// Panics if reassignment encounters malformed assignment state, or under
/// [`StrandedAssignment::Halt`] if an expired assignment has no eligible operator.
fn process_bridge_txs<C: ClaimVersion>(
    state: &mut BridgeStateV1,
    txs: &[TxInputRef<'_>],
    header_vs: &HeaderVerificationState,
    verified_aux_data: &VerifiedAuxData,
    relayer: &mut impl MsgRelayer,
    stranded: StrandedAssignment,
) {
    // Process each transaction
    for tx in txs {
        // Parse transaction to extract structured data (deposit/withdrawal info)
        // then handle the parsed transaction to update state and emit events.
        // Transactions that are not directly processed by the bridge subprotocol
        // (e.g. `DepositRequest`, `Commit`) or are otherwise unparseable are silently skipped.
        let Some(parsed_tx) = parse_tx(tx) else {
            continue;
        };
        match handle_parsed_tx::<C>(state, parsed_tx, verified_aux_data, relayer) {
            // `handle_parsed_tx` already emits a type-specific info log on success, so this
            // is only a coarse trace marker. `txid` is computed inside the macro, because
            // logging is compiled to noop in ZkVM.
            Ok(()) => debug!(txid = %tx.tx().compute_txid(), "Processed bridge tx"),
            Err(e) => {
                error!(txid = %tx.tx().compute_txid(), error = %e, "Failed to process bridge tx")
            }
        }
    }

    // After processing all transactions, reassign expired assignments
    let report = match state.reassign_expired_assignments(&header_vs.last_verified_block) {
        Ok(report) => report,
        Err(e) => {
            error!(
                l1_height = header_vs.last_verified_block.height(),
                error = %e,
                "Failed to reassign expired assignments because assignment state is invalid"
            );
            panic!("Failed to reassign expired assignments {e}");
        }
    };

    if let StrandedAssignment::Halt = stranded
        && let Some(&deposit_idx) = report.newly_unassignable().first()
    {
        // PANIC: Failure to reassign expired assignments indicates a violation of the bridge's
        // fundamental 1/N honesty assumption. This means no operators remain available to
        // fulfill withdrawals, representing an unrecoverable protocol breach that poses
        // significant risk of fund loss. The pass lists stranded deposits in deposit order, so
        // this names the deposit the released pass stopped at, with the error it raised.
        let e = WithdrawalAssignmentError::NoEligibleOperators { deposit_idx };
        error!(
            l1_height = header_vs.last_verified_block.height(),
            error = %e,
            "Failed to reassign expired assignments; 1/N honesty assumption violated"
        );
        panic!("Failed to reassign expired assignments {e}");
    }

    // Only log when something actually happened, to avoid a line every block.
    if let Some(first_deposit_idx) = report.reassigned().first() {
        let first = state
            .assignments()
            .get_assignment(*first_deposit_idx)
            .expect("reassignment report references a stored assignment");
        info!(
            count = report.reassigned().len(),
            l1_height = header_vs.last_verified_block.height(),
            // Uniform across the batch: all entries get the same new deadline.
            fulfillment_deadline = first.fulfillment_deadline(),
            "Reassigned expired withdrawal assignments",
        );
        for deposit_idx in report.reassigned() {
            let assignment = state
                .assignments()
                .get_assignment(*deposit_idx)
                .expect("reassignment report references a stored assignment");
            info!(
                deposit_idx = assignment.deposit_idx(),
                operator_idx = assignment.current_assignee(),
                "Reassigned withdrawal to new operator",
            );
        }
    }

    for deposit_idx in report.newly_unassignable() {
        let assignment = state
            .assignments()
            .get_assignment(*deposit_idx)
            .expect("reassignment report references a stored assignment");
        warn!(
            deposit_idx,
            notary_set = assignment.notary_set(),
            current_assignee = assignment.current_assignee(),
            "Withdrawal assignment has no active operator from its historical notary set",
        );
    }

    // Publish the accumulated proof of work as the bridge container's export `extra_data`,
    // so downstream consumers can read the verified L1 work directly from the export state.
    let accumulated_pow = header_vs.total_accumulated_pow().to_le_bytes();
    let extra_data_log = ExportExtraDataUpdate::new(BRIDGE_SUBPROTOCOL_ID, accumulated_pow);
    relayer.emit_log(
        AsmLogEntry::from_log(&extra_data_log)
            .expect("export extra data log encoding is infallible for fixed-size SSZ"),
    );
}

/// Applies every bridge message in `msgs`.
///
/// # Panics
///
/// Panics if withdrawal assignment creation fails; see [`BridgeSubproto`].
fn process_bridge_msgs(
    state: &mut BridgeStateV1,
    msgs: &[BridgeIncomingMsg],
    l1ref: &L1BlockCommitment,
) {
    for msg in msgs {
        match msg {
            BridgeIncomingMsg::DispatchWithdrawal(payload) => {
                // Decompose the batch intent into per-denomination intents, then for each one
                // create an assignment, log it, and insert it (consuming the deposit that
                // backs it). A non-decomposable amount (not a whole multiple of the
                // denomination) surfaces here as an amount mismatch.
                let denomination = *state.denomination();
                let result = payload
                    .decompose(denomination)
                    .ok_or_else(|| {
                        WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(Mismatch {
                            expected: denomination.to_sat(),
                            got: payload.amt().to_sat(),
                        })
                    })
                    .and_then(|intents| {
                        for intent in intents {
                            let assignment = state.create_withdrawal_assignment(&intent, l1ref)?;
                            info!(
                                deposit_idx = assignment.deposit_idx(),
                                assignee = assignment.current_assignee(),
                                amount_sat = assignment.withdrawal_output().amt().to_sat(),
                                fulfillment_deadline = assignment.fulfillment_deadline(),
                                selected_operator = %intent.selected_operator(),
                                "Created withdrawal assignment",
                            );
                            state.insert_withdrawal_assignment(assignment);
                        }
                        Ok(())
                    });
                if let Err(e) = result {
                    // PANIC: Withdrawal assignment failure indicates catastrophic system
                    // compromise.
                    error!(
                        l1_height = l1ref.height(),
                        error = %e,
                        "Failed to create withdrawal assignment"
                    );
                    panic!("Failed to create withdrawal assignment: {e}",);
                }
            }
            BridgeIncomingMsg::UpdateOperatorSet(payload) => {
                let add_members = &payload.add_members;
                let remove_members = &payload.remove_members;
                info!(
                    added = add_members.len(),
                    removed = remove_members.len(),
                    "Applying operator set update from admin subprotocol",
                );
                state.apply_operator_set_update(add_members, remove_members);
            }

            BridgeIncomingMsg::UpdateSafeHarborAddress(address) => {
                // Only claim success when the update actually applied; rejection (safe harbor
                // already activated) is warned inside `update_safe_harbor_address`.
                if state.update_safe_harbor_address(address.clone()) {
                    info!("Updated safe harbor address from admin subprotocol");
                }
            }

            BridgeIncomingMsg::Defcon(_) => {
                state.activate_safe_harbor();
                info!(
                    active_address = ?state.safe_harbor().address(),
                    "Activated safe harbor on Defcon signal from admin subprotocol"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_bridge_types::{SafeHarborAddress, WithdrawalIntent};
    use strata_asm_common::{HeaderVerificationState, Subprotocol};
    use strata_asm_logs::DepositLog;
    use strata_asm_proto_bridge_msgs::{BridgeIncomingMsg, DefconPayload};
    use strata_asm_proto_bridge_state::{AssignmentStatus, BridgeStateV1};
    use strata_asm_proto_bridge_txs::{
        deposit_request::DrtHeaderAux,
        test_utils::{create_drt_takeback_witness, create_test_operators, parse_sps50_tx},
    };
    use strata_btc_types::BitcoinAmount;
    use strata_identifiers::L1BlockCommitment;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::{BridgeStateV2, BridgeSubprotoV1, BridgeSubprotoV2, BridgeSubprotoV3};
    use crate::test_utils::{
        MockMsgRelayer, add_deposits, create_test_state, create_verified_aux_data,
        setup_deposit_tx_test,
    };

    /// Counts the [`DepositLog`]s emitted through `relayer`.
    fn deposit_log_count(relayer: &MockMsgRelayer) -> usize {
        relayer
            .logs()
            .iter()
            .filter(|log| log.try_into_log::<DepositLog>().is_ok())
            .count()
    }

    /// The claim version moves the export leaf, not the section. Both versions must therefore
    /// keep the same subprotocol ID and schema version, so that a spec activation between them
    /// needs no state migration and the section stays decodable under either.
    #[test]
    fn claim_versions_share_the_section_identity() {
        assert_eq!(BridgeSubprotoV1::ID, BridgeSubprotoV2::ID);
        assert_eq!(
            BridgeSubprotoV1::STATE_VERSION,
            BridgeSubprotoV2::STATE_VERSION
        );
    }

    /// The schema-1 subprotocol replaces the same section: same ID, next schema version.
    #[test]
    fn v3_moves_the_section_schema_only() {
        assert_eq!(BridgeSubprotoV3::ID, BridgeSubprotoV1::ID);
        assert_eq!(BridgeSubprotoV1::STATE_VERSION, 0);
        assert_eq!(BridgeSubprotoV3::STATE_VERSION, 1);
    }

    /// The safe harbor must start deactivated so it has no effect until the
    /// admin subprotocol explicitly triggers a defcon signal.
    #[test]
    fn safe_harbor_starts_deactivated() {
        let (state, _privkeys) = create_test_state();
        assert!(!state.safe_harbor().is_activated());
        assert_eq!(state.safe_harbor().active_address(), None);
    }

    #[test]
    fn process_msgs_update_safe_harbor_address() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let new_address: SafeHarborAddress = ArbitraryGenerator::new().generate();
        let msgs = vec![BridgeIncomingMsg::UpdateSafeHarborAddress(
            new_address.clone(),
        )];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert_eq!(state.safe_harbor().address(), &new_address);
        // Address updates alone must not activate the safe harbor.
        assert!(!state.safe_harbor().is_activated());
    }

    /// A `DispatchWithdrawal` for `N * denomination` must decompose into `N` assignments, each
    /// consuming one deposit.
    #[test]
    fn process_msgs_dispatch_withdrawal_creates_assignments() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        add_deposits(&mut state, 5);

        let mut intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
        intent.amt = BitcoinAmount::try_from(state.denomination().to_sat() * 3)
            .expect("test amount must be within the Bitcoin money supply");

        let msgs = vec![BridgeIncomingMsg::DispatchWithdrawal(intent)];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert_eq!(state.assignments().len(), 3);
        assert_eq!(state.deposits().len(), 2);
    }

    /// A `DispatchWithdrawal` whose amount is not a whole multiple of the denomination cannot be
    /// decomposed. This surfaces as an amount mismatch and, per the peg-safety contract, panics.
    #[test]
    #[should_panic(expected = "Failed to create withdrawal assignment")]
    fn process_msgs_dispatch_non_multiple_amount_panics() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let mut intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
        intent.amt = BitcoinAmount::try_from(state.denomination().to_sat() + 1)
            .expect("test amount must be within the Bitcoin money supply");

        let msgs = vec![BridgeIncomingMsg::DispatchWithdrawal(intent)];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);
    }

    /// After processing transactions, `process_txs` reassigns every assignment whose deadline has
    /// passed as of the last verified block, refreshing each to the new deadline.
    #[test]
    fn process_txs_reassigns_expired_assignments() {
        let (mut state, _privkeys) = create_test_state();

        // Anchor the assignments at height 0 so their deadline is the assignment duration (144).
        let creation_block = L1BlockCommitment::new(0, ArbitraryGenerator::new().generate());
        add_deposits(&mut state, 3);
        for _ in 0..3 {
            let mut intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
            intent.amt = *state.denomination();
            let assignment = state
                .create_withdrawal_assignment(&intent, &creation_block)
                .expect("creating an assignment for a matching deposit should succeed");
            state.insert_withdrawal_assignment(assignment);
        }

        // Advance well past the deadline so every assignment is expired — only
        // `last_verified_block` matters to `process_txs`.
        let current_height: u32 = 500;
        let mut header_vs = HeaderVerificationState::default();
        header_vs.last_verified_block =
            L1BlockCommitment::new(current_height, ArbitraryGenerator::new().generate());

        let aux_data = create_verified_aux_data(vec![]);
        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV1::process_txs(&mut state, &[], &header_vs, &aux_data, &mut relayer);

        // Reassignment refreshes each deadline to `current_height + assignment_duration`.
        let expected_deadline = current_height + 144;
        assert_eq!(state.assignments().len(), 3);
        for assignment in state.assignments().assignments() {
            assert_eq!(assignment.fulfillment_deadline(), expected_deadline);
        }
    }

    /// A deposit-shaped sweep of a DRT through the depositor's takeback leaf must leave the bridge
    /// state untouched and emit no deposit log, so the index it names stays free for the
    /// operators' key-path deposit of the same DRT.
    ///
    /// This is a synthetic subprotocol-level test: the sweep is the honest deposit with only the
    /// witness of input 0 swapped for a takeback spend, and each is fed to `process_txs` on its
    /// own.
    #[test]
    fn process_txs_ignores_takeback_sweep_and_keeps_deposit_idx_free() {
        let (mut state, operators) = create_test_state();
        let drt_aux: DrtHeaderAux = ArbitraryGenerator::new().generate();
        let (aux_data, info, deposit_tx) = setup_deposit_tx_test(
            &drt_aux,
            *state.denomination(),
            state.recovery_delay(),
            &operators,
        );
        let deposit_idx = info.header_aux().deposit_idx();

        let mut sweep_tx = deposit_tx.clone();
        sweep_tx.input[0].witness = create_drt_takeback_witness(
            &drt_aux,
            state.operators().agg_key().to_xonly_public_key(),
            state.recovery_delay(),
        );

        let header_vs = HeaderVerificationState::default();

        // `BridgeStateV1` has no `PartialEq`; its `Debug` output covers every field.
        let state_before = format!("{state:?}");
        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV1::process_txs(
            &mut state,
            &[parse_sps50_tx(&sweep_tx)],
            &header_vs,
            &aux_data,
            &mut relayer,
        );
        assert_eq!(
            format!("{state:?}"),
            state_before,
            "sweep must not touch state"
        );
        assert_eq!(
            deposit_log_count(&relayer),
            0,
            "sweep must not credit a deposit"
        );
        assert!(state.deposits().get_deposit(deposit_idx).is_none());

        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV1::process_txs(
            &mut state,
            &[parse_sps50_tx(&deposit_tx)],
            &header_vs,
            &aux_data,
            &mut relayer,
        );
        assert_eq!(
            deposit_log_count(&relayer),
            1,
            "honest deposit must be credited"
        );
        assert!(state.deposits().get_deposit(deposit_idx).is_some());
    }

    /// A deposit naming an index with a live assignment is ignored, even when it is a valid
    /// key-path spend, and the next dispatch still succeeds. Once the assignment is gone the
    /// index is accepted again.
    ///
    /// Synthetic: the operators' own deposit is replayed through `process_txs`, standing in for
    /// any N/N-signed deposit that names an assigned index (an operator bug, or a takeback sweep
    /// confirmed before the key-path rule applied). Without the check, the replay would be
    /// admitted and the next dispatch would panic on the duplicate assignment.
    #[test]
    fn process_txs_ignores_deposit_at_assigned_idx() {
        let (mut state, operators) = create_test_state();
        let drt_aux: DrtHeaderAux = ArbitraryGenerator::new().generate();
        let (aux_data, info, deposit_tx) = setup_deposit_tx_test(
            &drt_aux,
            *state.denomination(),
            state.recovery_delay(),
            &operators,
        );
        let deposit_idx = info.header_aux().deposit_idx();
        let header_vs = HeaderVerificationState::default();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();
        let dispatch_one = |state: &mut BridgeStateV1| {
            let mut intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
            intent.amt = *state.denomination();
            let msgs = vec![BridgeIncomingMsg::DispatchWithdrawal(intent)];
            BridgeSubprotoV1::process_msgs(state, &msgs, &l1ref);
        };

        // 1. The deposit lands and a withdrawal assigns it.
        let mut relayer = MockMsgRelayer::default();
        let txs = [parse_sps50_tx(&deposit_tx)];
        BridgeSubprotoV1::process_txs(&mut state, &txs, &header_vs, &aux_data, &mut relayer);
        dispatch_one(&mut state);
        assert!(state.assignments().get_assignment(deposit_idx).is_some());
        assert_eq!(state.deposits().len(), 0);

        // 2. A second deposit at the assigned index is ignored.
        let state_before = format!("{state:?}");
        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV1::process_txs(&mut state, &txs, &header_vs, &aux_data, &mut relayer);
        assert_eq!(format!("{state:?}"), state_before, "state must not change");
        assert_eq!(
            deposit_log_count(&relayer),
            0,
            "deposit must not be credited"
        );

        // 3. The next dispatch consumes a fresh deposit instead of panicking.
        add_deposits(&mut state, 1);
        dispatch_one(&mut state);
        assert_eq!(state.assignments().len(), 2);
        assert_eq!(state.deposits().len(), 0);

        // 4. Once the assignment is removed (as fulfillment does), the index carries no state and
        //    is free again.
        state
            .remove_assignment(deposit_idx)
            .expect("assignment for the deposit is live");
        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV1::process_txs(&mut state, &txs, &header_vs, &aux_data, &mut relayer);
        assert_eq!(deposit_log_count(&relayer), 1);
        assert!(state.deposits().get_deposit(deposit_idx).is_some());
    }

    /// A state with one assignment stranded by a full operator-set turnover, one healthy
    /// assignment made afterwards, and a header at a height past both deadlines.
    struct StrandedFixture {
        state: BridgeStateV1,
        header_vs: HeaderVerificationState,
        stranded_idx: u32,
        stranded_assignee: u32,
        stranded_deadline: u32,
        healthy_idx: u32,
    }

    const STRANDED_FIXTURE_HEIGHT: u32 = 500;

    fn stranded_fixture() -> StrandedFixture {
        let (mut state, _privkeys) = create_test_state();
        let creation_block = L1BlockCommitment::new(0, ArbitraryGenerator::new().generate());

        add_deposits(&mut state, 1);
        let mut old_intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
        old_intent.amt = *state.denomination();
        let old_assignment = state
            .create_withdrawal_assignment(&old_intent, &creation_block)
            .unwrap();
        let stranded_idx = old_assignment.deposit_idx();
        let stranded_assignee = old_assignment.current_assignee();
        let stranded_deadline = old_assignment.fulfillment_deadline();
        state.insert_withdrawal_assignment(old_assignment);

        let initial_operator_count = state.operators().len();
        let (_, replacement_operators) = create_test_operators(2);
        let removed_operators: Vec<_> = (0..initial_operator_count).collect();
        state.apply_operator_set_update(&replacement_operators, &removed_operators);

        add_deposits(&mut state, 1);
        let mut healthy_intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
        healthy_intent.amt = *state.denomination();
        let healthy_assignment = state
            .create_withdrawal_assignment(&healthy_intent, &creation_block)
            .unwrap();
        let healthy_idx = healthy_assignment.deposit_idx();
        state.insert_withdrawal_assignment(healthy_assignment);

        let mut header_vs = HeaderVerificationState::default();
        header_vs.last_verified_block = L1BlockCommitment::new(
            STRANDED_FIXTURE_HEIGHT,
            ArbitraryGenerator::new().generate(),
        );

        StrandedFixture {
            state,
            header_vs,
            stranded_idx,
            stranded_assignee,
            stranded_deadline,
            healthy_idx,
        }
    }

    /// The schema-1 subprotocol marks the stranded assignment unassignable, leaves its
    /// assignee and deadline alone, and still reassigns the healthy one.
    #[test]
    fn v3_process_txs_marks_stranded_assignment_and_reassigns_healthy_assignment() {
        let fixture = stranded_fixture();
        let mut state = BridgeStateV2::from(fixture.state);

        let aux_data = create_verified_aux_data(vec![]);
        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV3::process_txs(&mut state, &[], &fixture.header_vs, &aux_data, &mut relayer);

        let stranded = state
            .assignments()
            .get_assignment(fixture.stranded_idx)
            .unwrap();
        assert_eq!(stranded.status(), AssignmentStatus::Unassignable);
        assert_eq!(stranded.current_assignee(), fixture.stranded_assignee);
        assert_eq!(stranded.fulfillment_deadline(), fixture.stranded_deadline);

        let healthy = state
            .assignments()
            .get_assignment(fixture.healthy_idx)
            .unwrap();
        assert_eq!(healthy.status(), AssignmentStatus::Active);
        assert_eq!(
            healthy.fulfillment_deadline(),
            STRANDED_FIXTURE_HEIGHT + 144
        );
        assert!(
            !relayer.logs().is_empty(),
            "block processing should complete"
        );
    }

    /// The released subprotocol still fails the block on a stranded assignment, with the error
    /// it has always raised, because schema 0 cannot record the assignment as unassignable.
    #[test]
    #[should_panic(
        expected = "Failed to reassign expired assignments No current multisig operator found in \
                    deposit's notary operators for deposit index"
    )]
    fn v1_process_txs_halts_on_stranded_assignment() {
        let mut fixture = stranded_fixture();
        let aux_data = create_verified_aux_data(vec![]);
        let mut relayer = MockMsgRelayer::default();
        BridgeSubprotoV1::process_txs(
            &mut fixture.state,
            &[],
            &fixture.header_vs,
            &aux_data,
            &mut relayer,
        );
    }

    #[test]
    fn process_msgs_defcon_activates_safe_harbor() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let msgs = vec![BridgeIncomingMsg::Defcon(DefconPayload::default())];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert!(state.safe_harbor().is_activated());
        assert_eq!(
            state.safe_harbor().active_address(),
            Some(state.safe_harbor().address())
        );
    }

    /// Once the safe harbor is activated, the address must be frozen so
    /// bridge nodes see a single sweep destination. Allowing it to change
    /// mid-sweep would split funds across two addresses with no coherent
    /// destination for the bridge node to drive the rest of the sweep to.
    #[test]
    fn process_msgs_update_after_activation_is_rejected() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let original_address = state.safe_harbor().address().clone();

        let rejected_address: SafeHarborAddress = ArbitraryGenerator::new().generate();
        let msgs = vec![
            BridgeIncomingMsg::Defcon(DefconPayload::default()),
            BridgeIncomingMsg::UpdateSafeHarborAddress(rejected_address),
        ];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert!(state.safe_harbor().is_activated());
        // Address must be unchanged from before the rejected update.
        assert_eq!(state.safe_harbor().address(), &original_address);
        assert_eq!(
            state.safe_harbor().active_address(),
            Some(&original_address)
        );
    }
}
