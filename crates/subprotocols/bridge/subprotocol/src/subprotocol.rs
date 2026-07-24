//! Bridge V1 Subprotocol Implementation
//!
//! This module contains the core subprotocol implementation that integrates
//! with the Strata Anchor State Machine (ASM).

use strata_asm_common::{
    AsmLogEntry, AuxRequestCollector, HeaderVerificationState, MsgRelayer, Subprotocol,
    SubprotocolId, TxInputRef, VerifiedAuxData,
    logging::{debug, error, info},
};
use strata_asm_logs::ExportExtraDataUpdate;
use strata_asm_params::BridgeInitConfig;
use strata_asm_proto_bridge_msgs::BridgeIncomingMsg;
use strata_asm_proto_bridge_state::BridgeStateV1;
use strata_asm_proto_bridge_txs::{BRIDGE_SUBPROTOCOL_ID, errors::Mismatch, parser::parse_tx};
use strata_identifiers::L1BlockCommitment;

use crate::{
    errors::WithdrawalAssignmentError,
    handler::{handle_parsed_tx, preprocess_parsed_tx},
};

/// Bridge V1 subprotocol implementation.
///
/// This struct implements the [`Subprotocol`] trait to integrate the bridge functionality
/// with the ASM. It handles Bitcoin deposit processing, operator management, and withdrawal
/// coordination.
#[derive(Copy, Clone, Debug)]
pub struct BridgeSubprotoV1;

impl Subprotocol for BridgeSubprotoV1 {
    const ID: SubprotocolId = BRIDGE_SUBPROTOCOL_ID;

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

    /// Processes transactions and reassigns expired assignments.
    ///
    /// The function follows a two-phase approach:
    /// 1. **Transaction processing**: Handles incoming bridge transactions
    /// 2. **Post-processing**: Reassigns any expired assignments to new operators
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
        // Process each transaction
        for tx in txs {
            // Parse transaction to extract structured data (deposit/withdrawal info)
            // then handle the parsed transaction to update state and emit events.
            // Transactions that are not directly processed by the bridge subprotocol
            // (e.g. `DepositRequest`, `Commit`) or are otherwise unparseable are silently skipped.
            let Some(parsed_tx) = parse_tx(tx) else {
                continue;
            };
            match handle_parsed_tx(state, parsed_tx, verified_aux_data, relayer) {
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
        match state.reassign_expired_assignments(&header_vs.last_verified_block) {
            Ok(reassigned) => {
                // Only log when something actually happened, to avoid a line every block.
                if let Some(first) = reassigned.first() {
                    info!(
                        count = reassigned.len(),
                        l1_height = header_vs.last_verified_block.height(),
                        // Uniform across the batch: all entries get the same new deadline.
                        fulfillment_deadline = first.fulfillment_deadline(),
                        "Reassigned expired withdrawal assignments",
                    );
                    for assignment in &reassigned {
                        info!(
                            deposit_idx = assignment.deposit_idx(),
                            operator_idx = assignment.current_assignee(),
                            "Reassigned withdrawal to new operator",
                        );
                    }
                }
            }
            Err(e) => {
                // PANIC: Failure to reassign expired assignments indicates a violation of the
                // bridge's fundamental 1/N honesty assumption. This means no operators remain
                // available to fulfill withdrawals, representing an unrecoverable protocol breach
                // that poses significant risk of fund loss.
                error!(
                    l1_height = header_vs.last_verified_block.height(),
                    error = %e,
                    "Failed to reassign expired assignments; 1/N honesty assumption violated"
                );
                panic!("Failed to reassign expired assignments {e}");
            }
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
                                let assignment =
                                    state.create_withdrawal_assignment(&intent, l1ref)?;
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

                BridgeIncomingMsg::UpdateSafeHarbourAddress(address) => {
                    // Only claim success when the update actually applied; rejection (safe harbour
                    // already activated) is warned inside `update_safe_harbour_address`.
                    if state.update_safe_harbour_address(address.clone()) {
                        info!("Updated safe harbour address from admin subprotocol");
                    }
                }

                BridgeIncomingMsg::Defcon(_) => {
                    state.activate_safe_harbour();
                    info!(
                        active_address = ?state.safe_harbour().address(),
                        "Activated safe harbour on Defcon signal from admin subprotocol"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{HeaderVerificationState, Subprotocol};
    use strata_asm_proto_bridge_msgs::{BridgeIncomingMsg, DefconPayload};
    use strata_asm_proto_bridge_types::{SafeHarbourAddress, WithdrawalIntent};
    use strata_btc_types::BitcoinAmount;
    use strata_identifiers::L1BlockCommitment;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::BridgeSubprotoV1;
    use crate::test_utils::{
        MockMsgRelayer, add_deposits, create_test_state, create_verified_aux_data,
    };

    /// The safe harbour must start deactivated so it has no effect until the
    /// admin subprotocol explicitly triggers a defcon signal.
    #[test]
    fn safe_harbour_starts_deactivated() {
        let (state, _privkeys) = create_test_state();
        assert!(!state.safe_harbour().is_activated());
        assert_eq!(state.safe_harbour().active_address(), None);
    }

    #[test]
    fn process_msgs_update_safe_harbour_address() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let new_address: SafeHarbourAddress = ArbitraryGenerator::new().generate();
        let msgs = vec![BridgeIncomingMsg::UpdateSafeHarbourAddress(
            new_address.clone(),
        )];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert_eq!(state.safe_harbour().address(), &new_address);
        // Address updates alone must not activate the safe harbour.
        assert!(!state.safe_harbour().is_activated());
    }

    /// A `DispatchWithdrawal` for `N * denomination` must decompose into `N` assignments, each
    /// consuming one deposit.
    #[test]
    fn process_msgs_dispatch_withdrawal_creates_assignments() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        add_deposits(&mut state, 5);

        let mut intent: WithdrawalIntent = ArbitraryGenerator::new().generate();
        intent.amt = BitcoinAmount::from_sat(state.denomination().to_sat() * 3);

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
        intent.amt = BitcoinAmount::from_sat(state.denomination().to_sat() + 1);

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
        let mut relayer = MockMsgRelayer;
        BridgeSubprotoV1::process_txs(&mut state, &[], &header_vs, &aux_data, &mut relayer);

        // Reassignment refreshes each deadline to `current_height + assignment_duration`.
        let expected_deadline = current_height + 144;
        assert_eq!(state.assignments().len(), 3);
        for assignment in state.assignments().assignments() {
            assert_eq!(assignment.fulfillment_deadline(), expected_deadline);
        }
    }

    #[test]
    fn process_msgs_defcon_activates_safe_harbour() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let msgs = vec![BridgeIncomingMsg::Defcon(DefconPayload::default())];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert!(state.safe_harbour().is_activated());
        assert_eq!(
            state.safe_harbour().active_address(),
            Some(state.safe_harbour().address())
        );
    }

    /// Once the safe harbour is activated, the address must be frozen so
    /// bridge nodes see a single sweep destination. Allowing it to change
    /// mid-sweep would split funds across two addresses with no coherent
    /// destination for the bridge node to drive the rest of the sweep to.
    #[test]
    fn process_msgs_update_after_activation_is_rejected() {
        let (mut state, _privkeys) = create_test_state();
        let l1ref: L1BlockCommitment = ArbitraryGenerator::new().generate();

        let original_address = state.safe_harbour().address().clone();

        let rejected_address: SafeHarbourAddress = ArbitraryGenerator::new().generate();
        let msgs = vec![
            BridgeIncomingMsg::Defcon(DefconPayload::default()),
            BridgeIncomingMsg::UpdateSafeHarbourAddress(rejected_address),
        ];
        BridgeSubprotoV1::process_msgs(&mut state, &msgs, &l1ref);

        assert!(state.safe_harbour().is_activated());
        // Address must be unchanged from before the rejected update.
        assert_eq!(state.safe_harbour().address(), &original_address);
        assert_eq!(
            state.safe_harbour().active_address(),
            Some(&original_address)
        );
    }
}
