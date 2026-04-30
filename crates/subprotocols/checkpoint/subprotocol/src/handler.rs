use strata_asm_common::{AsmLogEntry, MsgRelayer, TxInputRef, VerifiedAuxData, logging};
use strata_asm_logs::CheckpointTipUpdate;
use strata_asm_proto_bridge_v1_msgs::{BridgeIncomingMsg, DispatchWithdrawalPayload};
use strata_asm_proto_checkpoint_txs::extract_checkpoint_from_envelope;
use strata_asm_proto_checkpoint_types::compute_asm_manifests_hash_from_leaves;
use strata_checkpoint_verification::{
    state::CheckpointState,
    verification::{
        ValidatedCheckpointWithdrawals, verify_progression,
        verify_proof_and_extract_withdrawal_intents,
    },
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
    let Ok(envelope) = extract_checkpoint_from_envelope(tx) else {
        logging::warn!("failed to extract checkpoint payload from envelope, ignoring");
        return;
    };
    let epoch = envelope.payload.new_tip().epoch;

    logging::debug!(epoch, "processing checkpoint transaction");

    // Phase 1: validate epoch / L1 / L2 progression. Yields the L1 range whose ASM
    // manifests we must hash for phase 2.
    let validated_range = match verify_progression(state, current_l1_height, &envelope) {
        Ok(r) => r,
        Err(e) => {
            logging::warn!(epoch, error = %e, "checkpoint progression verification failed");
            return;
        }
    };

    // Resolve the validated range to manifest hashes. Aux data MUST be available for any
    // range produced by phase 1 — failure here means the runtime did not honor the request
    // issued in `pre_process_txs`, not a checkpoint-level rejection.
    let manifest_hashes = verified_aux_data
        .get_manifest_hashes(
            validated_range.start_height() as u64,
            validated_range.end_height() as u64,
        )
        .unwrap_or_else(|e| {
            logging::error!(epoch, error = %e, "invalid aux data");
            panic!("invalid aux");
        });
    let asm_manifests_hash = compute_asm_manifests_hash_from_leaves(&manifest_hashes);

    // Phase 2: authenticate the envelope, verify the ZK proof against the precomputed
    // hash, and extract withdrawal intents.
    let validated = match verify_proof_and_extract_withdrawal_intents(
        state,
        &envelope,
        validated_range,
        asm_manifests_hash,
    ) {
        Ok(v) => v,
        Err(e) => {
            logging::warn!(epoch, error = %e, "checkpoint proof verification failed");
            return;
        }
    };

    let ValidatedCheckpointWithdrawals {
        withdrawal_intents,
        verified_withdrawals,
    } = validated;

    logging::info!(epoch, "checkpoint validated successfully");

    state.deduct_withdrawals(verified_withdrawals);

    let new_tip = envelope.payload.new_tip;
    state.update_verified_tip(new_tip);

    let checkpoint_tip_update = CheckpointTipUpdate::new(new_tip);
    let log_entry = AsmLogEntry::from_log(&checkpoint_tip_update)
        .expect("CheckpointTipUpdate encoding is infallible for fixed-size SSZ");
    relayer.emit_log(log_entry);

    for (output, selected_operator) in withdrawal_intents {
        let bridge_msg = BridgeIncomingMsg::DispatchWithdrawal(DispatchWithdrawalPayload {
            output,
            selected_operator,
        });
        relayer.relay_msg(&bridge_msg);
    }
}
