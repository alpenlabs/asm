//! Administration Subprotocol Implementation
//!
//! This module contains the core administration subprotocol implementation that integrates
//! with the Strata Anchor State Machine (ASM) for managing protocol governance and updates.

use strata_asm_admin_types::AdministrationInitConfig;
use strata_asm_common::{
    HeaderVerificationState, MsgRelayer, Subprotocol, SubprotocolId, TxInputRef, VerifiedAuxData,
    logging::{info, warn},
};
use strata_asm_proto_admin_msgs::AdministrationIncomingMsg;
use strata_asm_proto_admin_txs::{constants::ADMINISTRATION_SUBPROTOCOL_ID, parser::parse_tx};
use strata_identifiers::L1BlockCommitment;

use crate::{
    handler::{handle_action, handle_pending_updates},
    state::AdministrationSubprotoState,
};

/// Administration subprotocol implementation.
///
/// This struct implements the [`Subprotocol`] trait to integrate administration functionality
/// with the ASM. It handles multisig governance actions, protocol parameter updates, and
/// operator set management through a queued execution system.
#[derive(Debug)]
pub struct AdministrationSubprotocol;

impl Subprotocol for AdministrationSubprotocol {
    const ID: SubprotocolId = ADMINISTRATION_SUBPROTOCOL_ID;

    type InitConfig = AdministrationInitConfig;

    type State = AdministrationSubprotoState;

    type Msg = AdministrationIncomingMsg;

    fn init(config: &Self::InitConfig) -> AdministrationSubprotoState {
        AdministrationSubprotoState::new(config)
    }

    /// Processes transactions for the Administration subprotocol and executes pending updates.
    ///
    /// The function follows a two-phase approach:
    /// 1. **Pre-processing**: Executes all queued updates that are ready for activation
    /// 2. **Transaction processing**: Handles incoming multisig actions
    fn process_txs(
        state: &mut AdministrationSubprotoState,
        txs: &[TxInputRef<'_>],
        header_vs: &HeaderVerificationState,
        _verified_aux_data: &VerifiedAuxData,
        relayer: &mut impl MsgRelayer,
    ) {
        let current_height = header_vs.last_verified_block.height();

        // Phase 1: Execute any pending updates that have reached their activation height
        handle_pending_updates(state, relayer, current_height);

        // Phase 2: Process incoming administration transactions. Unparseable txs are
        // logged and skipped inside `parse_tx` to maintain system resilience.
        for tx in txs {
            let Some(signed_payload) = parse_tx(tx) else {
                continue;
            };
            if let Err(e) = handle_action(state, signed_payload, current_height, relayer) {
                warn!(tx_id = %tx.tx().compute_txid(), error = %e, "Failed to handle admin action");
            }
        }
    }

    /// Processes incoming administration messages.
    fn process_msgs(
        state: &mut AdministrationSubprotoState,
        msgs: &[Self::Msg],
        _l1ref: &L1BlockCommitment,
    ) {
        for msg in msgs {
            match msg {
                AdministrationIncomingMsg::OlTransitionsPruned(pruned) => {
                    debug_assert_eq!(
                        *pruned, 1,
                        "single-slot state can only prune one transition"
                    );
                    state.acknowledge_ol_transition_promoted();
                    info!(%pruned, "accounted for pruned checkpoint predicate transitions");
                }
            }
        }
    }
}
