use strata_asm_checkpoint_types::{AsmManifestRangeHash, compute_asm_manifests_hash_from_leaves};
use strata_asm_common::{AsmLogEntry, MsgRelayer, TxInputRef, VerifiedAuxData, logging};
use strata_asm_logs::CheckpointTipUpdate;
use strata_asm_proto_bridge_msgs::BridgeIncomingMsg;
use strata_checkpoint_verification::{CheckpointL1Range, CheckpointState, verify_progression};
use strata_identifiers::L1Height;

use crate::{auth::authenticate_checkpoint_tx, errors::CheckpointEnvelopeError};

/// Processes a checkpoint transaction from L1.
///
/// Extracts and validates the checkpoint payload from the transaction envelope.
/// If the payload cannot be extracted or validation fails, the transaction is
/// ignored and logged. On successful validation, updates the verified tip and
/// forwards any withdrawal intents to the bridge subprotocol.
///
/// # Panics
///
/// Panics if the required auxiliary data (the transaction spent by the envelope input, or the
/// ASM manifest hashes) is not provided.
pub(crate) fn handle_checkpoint_tx(
    state: &mut CheckpointState,
    tx: &TxInputRef<'_>,
    current_l1_height: L1Height,
    verified_aux_data: &VerifiedAuxData,
    relayer: &mut impl MsgRelayer,
) {
    // Authenticate the envelope before doing any progression or proof work.
    let payload = match authenticate_checkpoint_tx(state.sequencer_key(), tx, verified_aux_data) {
        Ok(payload) => payload,
        // `pre_process_txs` requests the spent transaction for every envelope that reaches this
        // lookup, so its absence means the runtime did not honor the request.
        Err(CheckpointEnvelopeError::MissingSpentOutput { outpoint, source }) => {
            logging::error!(
                txid = %tx.tx().compute_txid(),
                %outpoint,
                error = %source,
                "envelope spent output missing from verified aux data"
            );
            panic!("checkpoint aux data missing for envelope spent output {outpoint}: {source}");
        }
        Err(e) => {
            // `compute_txid` stays inside the macro: in zkVM the logging shim is a no-op
            // that discards its args, so the hash is never computed there.
            logging::warn!(
                txid = %tx.tx().compute_txid(),
                error = %e,
                "checkpoint envelope not authenticated, ignoring"
            );
            return;
        }
    };
    let epoch = payload.new_tip().epoch;

    logging::debug!(txid = %tx.tx().compute_txid(), epoch, "processing checkpoint transaction");

    // Validate epoch / L1 / L2 progression and confirm the covered territory lies wholly
    // inside the active predicate's range. Yields the L1 coverage whose ASM manifests we
    // must resolve before proof verification.
    let coverage = match verify_progression(
        state.verified_tip(),
        payload.new_tip(),
        current_l1_height,
        state.next_transition(),
    ) {
        Ok(c) => c,
        Err(e) => {
            logging::warn!(txid = %tx.tx().compute_txid(), epoch, error = %e, "checkpoint progression verification failed");
            return;
        }
    };

    // Derive the precomputed manifest hash committed to in the checkpoint claim. Empty
    // coverage commits to the zero hash; otherwise resolve the range from aux data.
    // Aux data MUST be available for any range produced by `verify_progression` —
    // failure here means the runtime did not honor the request issued in
    // `pre_process_txs`, not a checkpoint-level rejection.
    let asm_manifests_hash = match &coverage {
        CheckpointL1Range::Empty => AsmManifestRangeHash::ZERO,
        CheckpointL1Range::Range {
            start_height,
            end_height,
        } => {
            let manifest_hashes = verified_aux_data
                .get_manifest_hashes(*start_height as u64, *end_height as u64)
                .unwrap_or_else(|e| {
                    logging::error!(
                        txid = %tx.tx().compute_txid(),
                        epoch,
                        start_height,
                        end_height,
                        error = %e,
                        "manifest hashes missing from verified aux data"
                    );
                    panic!(
                        "checkpoint aux data missing for L1 range {start_height}..={end_height} \
                         (epoch {epoch}): {e}"
                    );
                });
            compute_asm_manifests_hash_from_leaves(&manifest_hashes)
        }
    };

    // Verify the ZK proof against the precomputed hash, extract withdrawal intents, and
    // atomically apply the resulting state changes.
    let withdrawal_intents = match state.advance(&payload, asm_manifests_hash) {
        Ok(v) => v,
        Err(e) => {
            logging::warn!(txid = %tx.tx().compute_txid(), epoch, error = %e, "checkpoint rejected");
            return;
        }
    };

    let new_tip = payload.new_tip;

    logging::info!(
        txid = %tx.tx().compute_txid(),
        new_tip = ?new_tip,
        withdrawals = withdrawal_intents.len(),
        "checkpoint validated"
    );

    let checkpoint_tip_update = CheckpointTipUpdate::new(new_tip);
    let log_entry = AsmLogEntry::from_log(&checkpoint_tip_update)
        .expect("CheckpointTipUpdate encoding is infallible for fixed-size SSZ");
    relayer.emit_log(log_entry);

    for intent in withdrawal_intents {
        let bridge_msg = BridgeIncomingMsg::DispatchWithdrawal(intent);
        relayer.relay_msg(&bridge_msg);
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{ScriptBuf, taproot::LeafVersion};
    use strata_asm_proto_txs_test_utils::parse_sps50_tx;

    use super::*;
    use crate::test_utils::{CheckpointFixture, RecordingRelayer, p2tr_script, witness_v2_script};

    /// Runs a sequencer-keyed checkpoint carrier through the handler and reports whether the
    /// verified tip advanced to the fixture's new tip, along with the number of emitted logs.
    fn handle_carrier(leaf_version: LeafVersion, prevout_script: ScriptBuf) -> (bool, usize) {
        let mut fixture = CheckpointFixture::new();
        let sequencer_key = fixture.sequencer_key();
        let (funding, carrier) =
            fixture.build_carrier(&sequencer_key, leaf_version, prevout_script);
        let verified_aux_data = fixture.verified_aux(&funding);

        let mut relayer = RecordingRelayer::default();
        handle_checkpoint_tx(
            &mut fixture.state,
            &parse_sps50_tx(&carrier),
            fixture.new_tip.l1_height() + 1,
            &verified_aux_data,
            &mut relayer,
        );

        let advanced = fixture.state.verified_tip() == &fixture.new_tip;
        (advanced, relayer.logs.len())
    }

    #[test]
    fn tapscript_leaf_on_p2tr_prevout_advances_tip() {
        let (advanced, logs) = handle_carrier(LeafVersion::TapScript, p2tr_script());

        assert!(advanced, "an authenticated checkpoint advances the tip");
        assert_eq!(logs, 1, "an accepted checkpoint emits one tip update log");
    }

    #[test]
    fn future_leaf_version_is_ignored() {
        let future = LeafVersion::from_consensus(0xc2).expect("0xc2 is a future leaf version");
        let (advanced, logs) = handle_carrier(future, p2tr_script());

        assert!(!advanced, "verified tip must not advance");
        assert_eq!(logs, 0, "a rejected checkpoint emits no logs");
    }

    #[test]
    fn unencumbered_prevout_is_ignored() {
        let (advanced, logs) = handle_carrier(LeafVersion::TapScript, witness_v2_script());

        assert!(!advanced, "verified tip must not advance");
        assert_eq!(logs, 0, "a rejected checkpoint emits no logs");
    }

    #[test]
    #[should_panic(expected = "checkpoint aux data missing for envelope spent output")]
    fn missing_prevout_aux_panics() {
        let mut fixture = CheckpointFixture::new();
        let sequencer_key = fixture.sequencer_key();
        let (_, carrier) =
            fixture.build_carrier(&sequencer_key, LeafVersion::TapScript, p2tr_script());
        let verified_aux_data = fixture.harness.gen_verified_aux(&fixture.new_tip);

        handle_checkpoint_tx(
            &mut fixture.state,
            &parse_sps50_tx(&carrier),
            fixture.new_tip.l1_height() + 1,
            &verified_aux_data,
            &mut RecordingRelayer::default(),
        );
    }
}
