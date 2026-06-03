//! Checkpoint Subprotocol Implementation

use strata_asm_common::{
    AuxRequestCollector, MsgRelayer, Subprotocol, SubprotocolId, TxInputRef, VerifiedAuxData,
    logging,
};
use strata_asm_params::CheckpointInitConfig;
use strata_asm_proto_checkpoint_msgs::CheckpointIncomingMsg;
use strata_asm_proto_checkpoint_txs::{
    CHECKPOINT_SUBPROTOCOL_ID, OL_STF_CHECKPOINT_TX_TYPE, extract_checkpoint_from_envelope,
};
use strata_checkpoint_verification::CheckpointState;
use strata_identifiers::L1BlockCommitment;

use crate::handler::handle_checkpoint_tx;

/// Checkpoint subprotocol implementation.
///
/// Implements the [`Subprotocol`] trait to integrate checkpoint verification
/// with the ASM. Responsibilities include:
///
/// - Processing checkpoint transactions (envelope pubkey verification, proof verification)
/// - Validating state transitions (epoch, L1/L2 range progression)
/// - Forwarding withdrawal intents to the bridge subprotocol
/// - Processing configuration updates from the admin subprotocol
#[derive(Copy, Clone, Debug)]
pub struct CheckpointSubprotocol;

impl Subprotocol for CheckpointSubprotocol {
    const ID: SubprotocolId = CHECKPOINT_SUBPROTOCOL_ID;

    type InitConfig = CheckpointInitConfig;
    type State = CheckpointState;
    type Msg = CheckpointIncomingMsg;

    fn init(config: &Self::InitConfig) -> Self::State {
        CheckpointState::init(config.clone())
    }

    fn pre_process_txs(
        state: &Self::State,
        txs: &[TxInputRef<'_>],
        collector: &mut AuxRequestCollector,
    ) {
        for tx in txs {
            if tx.tag().tx_type() == OL_STF_CHECKPOINT_TX_TYPE {
                match extract_checkpoint_from_envelope(tx) {
                    Ok(envelope) => {
                        // Skip request when the checkpoint covers no new L1 blocks
                        // (zero L1 progress). Mirrors the `CheckpointL1Range::Empty`
                        // branch in `handler.rs` so we never ask for an inverted range.
                        let prev_height = state.verified_tip().l1_height;
                        let new_height = envelope.payload.new_tip().l1_height;
                        if prev_height < new_height {
                            collector.request_manifest_hashes(
                                (prev_height + 1) as u64,
                                new_height as u64,
                            );
                        }
                    }
                    Err(e) => {
                        logging::warn!(
                            txid = %tx.tx().compute_txid(),
                            error = %e,
                            "Failed to parse checkpoint transaction in pre_process_txs"
                        );
                    }
                }
            }
        }
    }

    fn process_txs(
        state: &mut Self::State,
        txs: &[TxInputRef<'_>],
        l1ref: &L1BlockCommitment,
        verified_aux_data: &VerifiedAuxData,
        relayer: &mut impl MsgRelayer,
    ) {
        let current_l1_height = l1ref.height();

        for tx in txs {
            if tx.tag().tx_type() == OL_STF_CHECKPOINT_TX_TYPE {
                handle_checkpoint_tx(state, tx, current_l1_height, verified_aux_data, relayer)
            }
        }
    }

    fn process_msgs(state: &mut Self::State, msgs: &[Self::Msg], _l1ref: &L1BlockCommitment) {
        // ASM design assumes subprotocols are not adversarial against each other,
        // so no additional validation is performed on incoming messages.
        for msg in msgs {
            match msg {
                CheckpointIncomingMsg::DepositProcessed(amount) => {
                    logging::info!(amount_sat = amount.to_sat(), "Recording processed deposit");
                    state.record_deposit(*amount);
                }
                CheckpointIncomingMsg::UpdateSequencerKey(new_predicate) => {
                    logging::info!("Updating sequencer predicate");
                    state.update_sequencer_predicate(new_predicate.clone());
                }
                CheckpointIncomingMsg::UpdateCheckpointPredicate(new_predicate) => {
                    logging::info!("Updating checkpoint predicate");
                    state.update_checkpoint_predicate(new_predicate.clone());
                }
            }
        }
    }
}
