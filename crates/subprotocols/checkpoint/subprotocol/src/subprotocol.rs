//! Checkpoint Subprotocol Implementation

use strata_asm_checkpoint_types::{CheckpointInitConfig, PendingPredicateTransition};
use strata_asm_common::{
    AuxRequestCollector, HeaderVerificationState, MsgRelayer, SectionStateVersion, Subprotocol,
    SubprotocolId, TxInputRef, VerifiedAuxData, logging,
};
use strata_asm_proto_checkpoint_msgs::CheckpointIncomingMsg;
use strata_asm_proto_checkpoint_txs::{
    CHECKPOINT_SUBPROTOCOL_ID, OL_STF_CHECKPOINT_TX_TYPE, decode_checkpoint_payload,
};
use strata_checkpoint_verification::CheckpointState;
use strata_identifiers::L1BlockCommitment;

use crate::{auth::parse_sequencer_envelope, handler::handle_checkpoint_tx};

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
    const STATE_VERSION: SectionStateVersion = 0;

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
                request_checkpoint_aux(state, tx, collector);
            }
        }
    }

    fn process_txs(
        state: &mut Self::State,
        txs: &[TxInputRef<'_>],
        header_vs: &HeaderVerificationState,
        verified_aux_data: &VerifiedAuxData,
        relayer: &mut impl MsgRelayer,
    ) {
        let current_l1_height = header_vs.last_verified_block.height();

        for tx in txs {
            if tx.tag().tx_type() == OL_STF_CHECKPOINT_TX_TYPE {
                handle_checkpoint_tx(state, tx, current_l1_height, verified_aux_data, relayer)
            }
        }
    }

    fn process_msgs(state: &mut Self::State, msgs: &[Self::Msg], l1ref: &L1BlockCommitment) {
        // ASM design assumes subprotocols are not adversarial against each other,
        // so no additional validation is performed on incoming messages.
        for msg in msgs {
            match msg {
                CheckpointIncomingMsg::DepositProcessed(amount) => {
                    state.record_deposit(*amount);
                    logging::info!(
                        amount_sat = amount.to_sat(),
                        total_sat = state.available_deposit_sum(),
                        "recording processed deposit"
                    );
                }
                CheckpointIncomingMsg::UpdateSequencerKey(new_key) => {
                    logging::info!(
                        old = %state.sequencer_key(),
                        new = %new_key,
                        "updating sequencer key"
                    );
                    state.update_sequencer_key(*new_key);
                }
                CheckpointIncomingMsg::UpdateCheckpointPredicate(new_predicate) => {
                    // The message asks for the predicate to be updated, but we only
                    // queue it here: it takes effect once the verified tip passes the
                    // boundary. The block carrying the rotation is the last height the
                    // preceding predicate governs.
                    //
                    // A full queue drops its oldest entry, and that entry's key never
                    // activates. Administration already announced it with a
                    // `CheckpointPredicateEnacted` log at enactment and nothing retracts a
                    // log, so the OL sees a boundary the ASM does not honour. The ASM stays
                    // coherent — the preceding key governs on to the next boundary — and the
                    // OL is expected to handle the discrepancy.
                    let boundary = l1ref.height();
                    logging::info!(
                        boundary,
                        new = new_predicate.id(),
                        "recording checkpoint predicate transition"
                    );
                    state.queue_predicate_transition(PendingPredicateTransition::new(
                        new_predicate.clone(),
                        boundary,
                    ));
                }
            }
        }
    }
}

/// Requests the auxiliary data [`handle_checkpoint_tx`] needs for one checkpoint transaction.
///
/// Requests are issued exactly when the handler will read them: only for an envelope that passes
/// [`parse_sequencer_envelope`], the checks the handler runs before its first aux read. This also
/// keeps envelopes that anyone can post through a standard transaction from making the worker
/// fetch and prove data the handler would never use.
fn request_checkpoint_aux(
    state: &CheckpointState,
    tx: &TxInputRef<'_>,
    collector: &mut AuxRequestCollector,
) {
    let spend = match parse_sequencer_envelope(state.sequencer_key(), tx) {
        Ok(spend) => spend,
        Err(e) => {
            // The handler authoritatively warns on this same failure during
            // `process_txs`; keep this at debug to avoid double-logging per block.
            logging::debug!(
                txid = %tx.tx().compute_txid(),
                error = %e,
                "checkpoint envelope not authenticated in pre_process; skipping aux request"
            );
            return;
        }
    };

    // The handler authenticates the output this input spends.
    collector.request_bitcoin_tx(spend.spent_outpoint().txid);

    // The payload is not authenticated yet, but it only sizes the manifest request; the handler
    // authenticates it before reading the manifests.
    let payload = match decode_checkpoint_payload(spend.unverified_leaf().payload()) {
        Ok(payload) => payload,
        Err(e) => {
            logging::debug!(
                txid = %tx.tx().compute_txid(),
                error = %e,
                "failed to decode checkpoint payload in pre_process; skipping manifest request"
            );
            return;
        }
    };

    // Skip request when the checkpoint covers no new L1 blocks
    // (zero L1 progress). Mirrors the `CheckpointL1Range::Empty`
    // branch in `handler.rs` so we never ask for an inverted range.
    let prev_height = state.verified_tip().l1_height;
    let new_height = payload.new_tip().l1_height;
    if prev_height < new_height {
        logging::trace!(
            txid = %tx.tx().compute_txid(),
            start = prev_height + 1,
            end = new_height,
            "requesting manifest hashes"
        );
        collector.request_manifest_hashes((prev_height + 1) as u64, new_height as u64);
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Transaction, XOnlyPublicKey, key::Keypair, secp256k1::SECP256K1, taproot::LeafVersion,
    };
    use strata_asm_common::AuxRequests;
    use strata_asm_proto_txs_test_utils::parse_sps50_tx;

    use super::*;
    use crate::test_utils::{CheckpointFixture, p2tr_script};

    fn collect_requests(fixture: &CheckpointFixture, carrier: &Transaction) -> AuxRequests {
        let mut collector = AuxRequestCollector::new(u64::MAX);
        CheckpointSubprotocol::pre_process_txs(
            &fixture.state,
            &[parse_sps50_tx(carrier)],
            &mut collector,
        );
        collector.into_requests()
    }

    #[test]
    fn sequencer_tapscript_envelope_requests_prevout_and_manifests() {
        let fixture = CheckpointFixture::new();
        let (funding, carrier) = fixture.build_carrier(
            &fixture.sequencer_key(),
            LeafVersion::TapScript,
            p2tr_script(),
        );

        let requests = collect_requests(&fixture, &carrier);

        let start = fixture.state.verified_tip().l1_height() as u64 + 1;
        let end = fixture.new_tip.l1_height() as u64;
        let ranges: Vec<_> = requests
            .manifest_hashes()
            .iter()
            .map(|range| (range.start_height(), range.end_height()))
            .collect();
        assert_eq!(ranges, vec![(start, end)]);
        assert_eq!(requests.bitcoin_txs(), &[funding.compute_txid().into()]);
    }

    #[test]
    fn future_leaf_version_envelope_requests_nothing() {
        let fixture = CheckpointFixture::new();
        let future = LeafVersion::from_consensus(0xc2).expect("0xc2 is a future leaf version");
        let (_, carrier) = fixture.build_carrier(&fixture.sequencer_key(), future, p2tr_script());

        let requests = collect_requests(&fixture, &carrier);

        assert!(requests.manifest_hashes().is_empty());
        assert!(requests.bitcoin_txs().is_empty());
    }

    #[test]
    fn non_sequencer_envelope_requests_nothing() {
        let fixture = CheckpointFixture::new();
        let other_key: XOnlyPublicKey = Keypair::from_seckey_slice(SECP256K1, &[0x42; 32])
            .expect("valid secret key")
            .x_only_public_key()
            .0;
        let (_, carrier) = fixture.build_carrier(&other_key, LeafVersion::TapScript, p2tr_script());

        let requests = collect_requests(&fixture, &carrier);

        assert!(requests.manifest_hashes().is_empty());
        assert!(requests.bitcoin_txs().is_empty());
    }
}
