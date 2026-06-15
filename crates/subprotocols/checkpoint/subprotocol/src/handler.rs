use strata_asm_common::{AsmLogEntry, MsgRelayer, TxInputRef, VerifiedAuxData, logging};
use strata_asm_logs::CheckpointTipUpdate;
use strata_asm_proto_bridge_v1_msgs::BridgeIncomingMsg;
use strata_asm_proto_checkpoint_txs::extract_checkpoint_from_envelope;
use strata_asm_proto_checkpoint_types::{
    AsmManifestRangeHash, compute_asm_manifests_hash_from_leaves,
};
use strata_checkpoint_verification::{
    CheckpointL1Range, CheckpointState, verify_progression, verify_sequencer_predicate,
};
use strata_identifiers::L1Height;

/// Processes a checkpoint transaction from L1.
///
/// Extracts and validates the checkpoint payload from the transaction envelope.
/// If the payload cannot be extracted or validation fails, the transaction is
/// ignored and logged. On successful validation, updates the verified tip and
/// forwards any withdrawal intents to the bridge subprotocol.
///
/// # Panics
///
/// Panics if the required auxiliary data (ASM manifest hashes) is not provided or withdrawal intent
/// has a malformed descriptor.
pub(crate) fn handle_checkpoint_tx(
    state: &mut CheckpointState,
    tx: &TxInputRef<'_>,
    current_l1_height: L1Height,
    verified_aux_data: &VerifiedAuxData,
    relayer: &mut impl MsgRelayer,
) {
    let envelope = match extract_checkpoint_from_envelope(tx) {
        Ok(envelope) => envelope,
        Err(e) => {
            // `compute_txid` stays inside the macro: in zkVM the logging shim is a no-op
            // that discards its args, so the hash is never computed there.
            logging::warn!(
                txid = %tx.tx().compute_txid(),
                error = %e,
                "failed to extract checkpoint payload from envelope, ignoring"
            );
            return;
        }
    };
    let epoch = envelope.payload.new_tip().epoch;

    logging::debug!(txid = %tx.tx().compute_txid(), epoch, "processing checkpoint transaction");

    // Authenticate the envelope against the sequencer predicate before doing any
    // progression or proof work.
    if let Err(e) =
        verify_sequencer_predicate(state.sequencer_predicate(), &envelope.envelope_pubkey)
    {
        logging::warn!(txid = %tx.tx().compute_txid(), epoch, error = %e, "checkpoint envelope authentication failed");
        return;
    }

    // Validate epoch / L1 / L2 progression. Yields the L1 coverage whose ASM manifests
    // we must resolve before proof verification.
    let coverage = match verify_progression(
        state.verified_tip(),
        envelope.payload.new_tip(),
        current_l1_height,
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
    let withdrawal_intents = match state.advance(&envelope.payload, asm_manifests_hash) {
        Ok(v) => v,
        Err(e) => {
            logging::warn!(txid = %tx.tx().compute_txid(), epoch, error = %e, "checkpoint rejected");
            return;
        }
    };

    let new_tip = envelope.payload.new_tip;

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
