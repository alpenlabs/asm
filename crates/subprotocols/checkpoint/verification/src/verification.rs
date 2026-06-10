use bitcoin_bosd::Descriptor;
use ssz::Encode;
use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_asm_proto_bridge_v1_types::{
    BRIDGE_GATEWAY_ACCT_SERIAL, OperatorSelection, WithdrawalIntent,
};
use strata_asm_proto_checkpoint_types::{
    CheckpointClaim, CheckpointPayload, CheckpointSidecar, CheckpointTip, L2BlockRange, OLLog,
    SimpleWithdrawalIntentLogData,
};
use strata_crypto::hash;
use strata_identifiers::L1Height;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido_logging as logging;

use crate::{
    CheckpointState,
    errors::{CheckpointValidationResult, InvalidCheckpointPayload, InvalidSequencerPredicate},
};

/// L1 block range of a checkpoint, returned by [`verify_progression`].
#[derive(Debug)]
pub enum CheckpointL1Range {
    /// Checkpoint covers no new L1 blocks beyond the previous verified tip. The ASM
    /// manifests hash supplied to [`CheckpointState::advance`] must be
    /// [`AsmManifestRangeHash::ZERO`](strata_asm_manifest_types::AsmManifestRangeHash::ZERO).
    Empty,
    /// Checkpoint covers an inclusive range of new L1 blocks. `verify_progression`
    /// guarantees `start_height <= end_height` for this variant.
    Range {
        /// First L1 block height covered by the new checkpoint (inclusive).
        start_height: u32,
        /// Last L1 block height covered by the new checkpoint (inclusive).
        end_height: u32,
    },
}

/// Validates the checkpoint's range against progression rules — epoch advances by
/// exactly 1, L1 height does not regress and stays strictly below the current L1 tip,
/// and L2 slot advances.
///
/// On success, returns a [`CheckpointL1Range`] describing the L1 blocks the new
/// checkpoint covers.
pub fn verify_progression(
    verified_tip: &CheckpointTip,
    new_tip: &CheckpointTip,
    current_l1_height: L1Height,
) -> CheckpointValidationResult<CheckpointL1Range> {
    // Validate epoch progression: each checkpoint must advance the epoch by exactly 1.
    let expected_epoch = verified_tip
        .epoch
        .checked_add(1)
        .ok_or(InvalidCheckpointPayload::EpochOverflow)?;
    if new_tip.epoch != expected_epoch {
        return Err(InvalidCheckpointPayload::InvalidEpoch {
            expected: expected_epoch,
            actual: new_tip.epoch,
        }
        .into());
    }

    let l1_height_covered_in_last_checkpoint = verified_tip.l1_height();
    let l1_height_covered_in_new_checkpoint = new_tip.l1_height();

    // Validate L1 progression: checkpoint must cover blocks strictly below the current L1
    // tip — the checkpoint transaction itself is contained in the L1 block at
    // `current_l1_height`, so it can only reference earlier blocks.
    if l1_height_covered_in_new_checkpoint >= current_l1_height {
        return Err(InvalidCheckpointPayload::CheckpointBeyondL1Tip {
            checkpoint_height: l1_height_covered_in_new_checkpoint,
            current_height: current_l1_height,
        }
        .into());
    }

    // L1 must not regress. Zero L1 progress (same height) is allowed.
    // NOTE: censorship prevention via ALLOWED_L1_LAG is planned for a future milestone.
    if l1_height_covered_in_last_checkpoint > l1_height_covered_in_new_checkpoint {
        return Err(InvalidCheckpointPayload::L1HeightRegresses {
            prev_height: l1_height_covered_in_last_checkpoint,
            new_height: l1_height_covered_in_new_checkpoint,
        }
        .into());
    }

    // Validate L2 progression: slot must strictly advance.
    let prev_slot = verified_tip.l2_commitment().slot();
    let new_slot = new_tip.l2_commitment().slot();
    if new_slot <= prev_slot {
        return Err(InvalidCheckpointPayload::L2SlotDoesNotAdvance {
            prev_slot,
            new_slot,
        }
        .into());
    }

    let coverage = if l1_height_covered_in_last_checkpoint == l1_height_covered_in_new_checkpoint {
        CheckpointL1Range::Empty
    } else {
        CheckpointL1Range::Range {
            start_height: l1_height_covered_in_last_checkpoint + 1,
            end_height: l1_height_covered_in_new_checkpoint,
        }
    };

    Ok(coverage)
}

/// Verifies the checkpoint ZK proof against the precomputed ASM manifests hash.
///
/// Reconstructs the full [`CheckpointClaim`] from the verified tip, the payload's new
/// tip, the sidecar fields, and the precomputed manifest hash, then runs the checkpoint
/// predicate against it.
pub(crate) fn verify_proof(
    state: &CheckpointState,
    payload: &CheckpointPayload,
    asm_manifests_hash: AsmManifestRangeHash,
) -> CheckpointValidationResult<()> {
    let claim = construct_full_claim(
        state.verified_tip(),
        payload.new_tip(),
        payload.sidecar(),
        asm_manifests_hash,
    )?;

    state
        .checkpoint_predicate()
        .verify_claim_witness(&claim.as_ssz_bytes(), payload.proof())
        .map_err(InvalidCheckpointPayload::CheckpointPredicateVerification)?;

    Ok(())
}

/// Verifies that the envelope pubkey is authorized by the sequencer predicate.
///
/// Uses the SPS-51 envelope trick: the envelope's taproot pubkey is checked against the
/// sequencer predicate. Bitcoin consensus already verified the script-spend signature,
/// so we only need to confirm the pubkey matches.
///
/// Dispatches on the predicate type:
/// - [`NeverAccept`](PredicateTypeId::NeverAccept): always rejects.
/// - [`AlwaysAccept`](PredicateTypeId::AlwaysAccept): always accepts (useful for testing).
/// - [`Bip340Schnorr`](PredicateTypeId::Bip340Schnorr): compares the envelope pubkey against the
///   predicate's condition bytes (the sequencer's x-only public key).
/// - [`Sp1Groth16`](PredicateTypeId::Sp1Groth16): not a valid sequencer predicate type.
/// - Unknown type IDs are rejected.
pub fn verify_sequencer_predicate(
    sequencer_predicate: &PredicateKey,
    envelope_pubkey: &[u8],
) -> CheckpointValidationResult<()> {
    let type_id = PredicateTypeId::try_from(sequencer_predicate.id())
        .map_err(|_| InvalidSequencerPredicate::UnknownPredicateType(sequencer_predicate.id()))?;

    match type_id {
        PredicateTypeId::NeverAccept => Err(InvalidSequencerPredicate::NeverAccept.into()),
        PredicateTypeId::AlwaysAccept => Ok(()),
        PredicateTypeId::Bip340Schnorr => {
            if envelope_pubkey != sequencer_predicate.condition() {
                Err(InvalidSequencerPredicate::PubkeyMismatch {
                    expected: sequencer_predicate.condition().to_vec(),
                    actual: envelope_pubkey.to_vec(),
                }
                .into())
            } else {
                Ok(())
            }
        }
        PredicateTypeId::Sp1Groth16 => {
            Err(InvalidSequencerPredicate::UnsupportedType(type_id).into())
        }
    }
}

/// Constructs a complete checkpoint claim for verification by combining the verified tip state
/// with the new checkpoint payload.
fn construct_full_claim(
    verified_tip: &CheckpointTip,
    new_tip: &CheckpointTip,
    sidecar: &CheckpointSidecar,
    asm_manifests_hash: AsmManifestRangeHash,
) -> CheckpointValidationResult<CheckpointClaim> {
    let l2_range = L2BlockRange::new(*verified_tip.l2_commitment(), new_tip.l2_commitment);

    let state_diff_hash = hash::raw(sidecar.ol_state_diff()).into();

    // Hash SSZ-encoded OL logs (convert to Vec for SSZ encoding)
    let ol_logs_vec = sidecar.ol_logs().to_vec();
    let ol_logs_hash = hash::raw(&ol_logs_vec.as_ssz_bytes()).into();
    // Reconstruct terminal_header_complement_hash from the sidecar data posted on L1.
    // The ZK proof committed to this same hash derived from the executed terminal header,
    // so matching it here cryptographically binds the sidecar fields to proven execution.
    let terminal_header_complement_hash = sidecar.terminal_header_complement().compute_hash();

    Ok(CheckpointClaim::new(
        new_tip.epoch,
        l2_range,
        asm_manifests_hash,
        state_diff_hash,
        ol_logs_hash,
        terminal_header_complement_hash,
    ))
}

/// Extracts and validates withdrawal intent logs from OL logs.
///
/// Filters OL logs from the bridge gateway account, validates that withdrawal intent
/// destination descriptors can be parsed, and returns the extracted withdrawal intents.
pub(crate) fn extract_withdrawal_intents(
    logs: &[OLLog],
) -> CheckpointValidationResult<Vec<WithdrawalIntent>> {
    let mut withdrawal_intents = Vec::new();

    for log in logs
        .iter()
        // Secondary guard: withdrawal-intent logs must come from the bridge gateway account.
        // Type id is the primary dispatch key (below), but emitter and type must agree.
        .filter(|l| l.account_serial() == BRIDGE_GATEWAY_ACCT_SERIAL)
    {
        // Dispatch on the log type id carried in the msg-fmt envelope, not the raw payload.
        // The bridge gateway may emit other log types; skip anything that isn't a
        // withdrawal-intent log, that isn't a valid envelope, or whose body fails to decode.
        let withdrawal_data = match log.try_into_log::<SimpleWithdrawalIntentLogData>() {
            Ok(data) => data,
            Err(e) => {
                logging::trace!(err = ?e, "skipping non-withdrawal-intent OL log");
                continue;
            }
        };

        // Parse destination descriptor; return error on malformed descriptors
        let destination = match Descriptor::from_bytes(withdrawal_data.dest()) {
            Ok(destination) => destination,
            Err(e) => {
                // CRITICAL: User funds are destroyed on L2 but cannot be withdrawn on L1.
                // Since the extraction is done after the proof verification, this should have been
                // a proper descriptor.
                logging::error!(error = %e, "Failed to parse withdrawal destination descriptor");
                return Err(InvalidCheckpointPayload::MalformedWithdrawalDestDesc.into());
            }
        };

        let selected_operator = OperatorSelection::from_raw(withdrawal_data.selected_operator);
        let withdraw_output =
            WithdrawalIntent::new(destination, withdrawal_data.amt().into(), selected_operator);
        withdrawal_intents.push(withdraw_output);
    }

    Ok(withdrawal_intents)
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;
    use ssz_types::VariableList;
    use strata_asm_manifest_types::AsmManifestRangeHash;
    use strata_asm_proto_bridge_v1_types::{BRIDGE_GATEWAY_ACCT_SERIAL, WithdrawalIntent};
    use strata_asm_proto_checkpoint_types::{
        CheckpointPayload, OLLog, SimpleWithdrawalIntentLogData, TerminalHeaderComplement,
    };
    use strata_identifiers::AccountSerial;
    use strata_msg_fmt::{Msg, OwnedMsg};
    use strata_predicate::PredicateKey;
    use strata_test_utils_checkpoint::CheckpointTestHarness;

    use crate::{
        CheckpointState,
        errors::{
            CheckpointValidationError, CheckpointValidationResult, InvalidCheckpointPayload,
            InvalidSequencerPredicate,
        },
        verification::{
            CheckpointL1Range, extract_withdrawal_intents, verify_progression,
            verify_sequencer_predicate,
        },
    };

    fn test_setup() -> (CheckpointState, CheckpointTestHarness) {
        let harness = CheckpointTestHarness::new_random();
        let state = CheckpointState::new(
            harness.sequencer_predicate(),
            harness.checkpoint_predicate(),
            *harness.verified_tip(),
        );
        (state, harness)
    }

    /// Drives the full progression + proof pipeline with a precomputed manifest hash.
    /// Skips sequencer authentication, which has its own dedicated tests.
    fn run_proof_pipeline(
        state: &mut CheckpointState,
        current_l1_height: u32,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
    ) -> CheckpointValidationResult<Vec<WithdrawalIntent>> {
        verify_progression(state.verified_tip(), payload.new_tip(), current_l1_height)?;
        state.advance(payload, asm_manifests_hash)
    }

    #[test]
    fn test_validate_checkpoint_success() {
        let (mut state, harness) = test_setup();
        let payload = harness.build_payload();
        let new_tip = *payload.new_tip();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(&new_tip);
        let current_l1_height = new_tip.l1_height + 1;

        verify_sequencer_predicate(state.sequencer_predicate(), harness.sequencer_pubkey())
            .expect("auth");
        let res = run_proof_pipeline(&mut state, current_l1_height, &payload, asm_manifests_hash);
        assert!(res.is_ok());
    }

    // --- Sequencer authentication ---

    #[test]
    fn test_wrong_envelope_pubkey() {
        let harness = CheckpointTestHarness::new_random();
        let err =
            verify_sequencer_predicate(&harness.sequencer_predicate(), &[0u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidSequencerPredicate(
                InvalidSequencerPredicate::PubkeyMismatch { .. }
            )
        ));
    }

    /// Even though Bitcoin would reject an envelope without an envelope_pubkey set,
    /// this test is an additional railguard checking that the ASM checkpoint verification
    /// **would reject it as well**.
    #[test]
    fn test_empty_envelope_pubkey_rejected() {
        let harness = CheckpointTestHarness::new_random();
        let err = verify_sequencer_predicate(&harness.sequencer_predicate(), &[]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidSequencerPredicate(
                InvalidSequencerPredicate::PubkeyMismatch { .. }
            )
        ));
    }

    #[test]
    fn test_always_accept_predicate_skips_pubkey_check() {
        let res = verify_sequencer_predicate(&PredicateKey::always_accept(), &[0xab; 32]);
        assert!(res.is_ok());
    }

    #[test]
    fn test_never_accept_predicate_always_rejects() {
        let err =
            verify_sequencer_predicate(&PredicateKey::never_accept(), &[0xab; 32]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidSequencerPredicate(
                InvalidSequencerPredicate::NeverAccept
            )
        ));
    }

    // --- Progression ---

    #[test]
    fn test_invalid_epoch_progression() {
        let harness = CheckpointTestHarness::new_random();
        let mut payload = harness.build_payload();
        payload.new_tip.epoch = harness.verified_tip().epoch + 2;
        let current_l1_height = payload.new_tip().l1_height + 1;

        let err = verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::InvalidEpoch { .. }
            )
        ));
    }

    #[test]
    fn test_new_tip_beyond_current_l1_height() {
        let harness = CheckpointTestHarness::new_random();
        let payload = harness.build_payload();
        let current_l1_height = payload.new_tip().l1_height - 1;

        let err = verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointBeyondL1Tip { .. }
            )
        ));
    }

    #[test]
    fn test_zero_l1_progress_is_accepted() {
        let harness = CheckpointTestHarness::new_random();

        // Build a tip that keeps the same L1 height (zero progress).
        let mut new_tip = harness.gen_new_tip();
        new_tip.l1_height = harness.verified_tip().l1_height;

        let payload = harness.build_payload_with_tip(new_tip);
        let current_l1_height = harness.verified_tip().l1_height + 1;

        let coverage =
            verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
                .expect("zero L1 progress is accepted");
        assert!(matches!(coverage, CheckpointL1Range::Empty));
    }

    #[test]
    fn test_new_l1_tip_goes_backwards() {
        let harness = CheckpointTestHarness::new_random();
        let mut payload = harness.build_payload();
        payload.new_tip.l1_height = harness.verified_tip().l1_height - 1;
        let current_l1_height = harness.verified_tip().l1_height + 1;

        let err = verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::L1HeightRegresses { .. }
            )
        ));
    }

    #[test]
    fn test_l2_slot_does_not_advance() {
        let harness = CheckpointTestHarness::new_random();
        let mut payload = harness.build_payload();
        // Set new L2 slot to be equal to the previous slot (no progression).
        payload.new_tip.l2_commitment = *harness.verified_tip().l2_commitment();
        let current_l1_height = payload.new_tip().l1_height + 1;

        let err = verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::L2SlotDoesNotAdvance { .. }
            )
        ));
    }

    // --- Proof verification + withdrawal extraction ---

    #[test]
    fn test_invalid_state_diff() {
        let (mut state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());
        let current_l1_height = payload.new_tip().l1_height + 1;

        // Modify the payload to include invalid state diff after proof generation.
        payload.sidecar.ol_state_diff = vec![99u8; 88].try_into().unwrap();

        let err = run_proof_pipeline(&mut state, current_l1_height, &payload, asm_manifests_hash)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
    }

    #[test]
    fn test_invalid_ol_logs() {
        let (mut state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());
        let current_l1_height = payload.new_tip().l1_height + 1;

        // Modify the payload to include OL Logs that wasn't covered by the proof.
        let dummy_log = OLLog::new(AccountSerial::zero(), Vec::new());
        payload.sidecar.ol_logs = VariableList::new(vec![dummy_log]).unwrap();

        let err = run_proof_pipeline(&mut state, current_l1_height, &payload, asm_manifests_hash)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
    }

    /// Builds a well-formed withdrawal-intent log payload (valid descriptor dest).
    fn sample_withdrawal_intent() -> SimpleWithdrawalIntentLogData {
        // P2WPKH descriptor: type tag 0x00 + 20-byte hash = 21 bytes.
        let dest = Descriptor::new_p2wpkh(&[0x14; 20]).to_bytes();
        SimpleWithdrawalIntentLogData::new(100_000, dest, 0)
            .expect("withdrawal intent creation should not fail")
    }

    #[test]
    fn test_extract_dispatches_on_log_type() {
        let withdrawal = sample_withdrawal_intent();

        // 1. Well-formed withdrawal-intent log from the gateway account -> extracted.
        let good = OLLog::from_log(BRIDGE_GATEWAY_ACCT_SERIAL, &withdrawal).unwrap();

        // 2. A different OL log type id (e.g. snark account update 0x02) from the gateway ->
        //    ignored.
        let other_type = OLLog::new(
            BRIDGE_GATEWAY_ACCT_SERIAL,
            OwnedMsg::new(0x02, vec![1, 2, 3]).unwrap().to_vec(),
        );

        // 3. Withdrawal-intent type but emitted by a non-gateway account -> ignored (account
        //    guard).
        let wrong_account = OLLog::from_log(AccountSerial::zero(), &withdrawal).unwrap();

        let logs = vec![good, other_type, wrong_account];
        let outputs = extract_withdrawal_intents(&logs).expect("extraction should succeed");

        // Only the well-formed gateway withdrawal-intent log produces an output.
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].amt(), withdrawal.amt().into());
    }

    #[test]
    fn test_invalid_terminal_header_complement() {
        let (mut state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());
        let current_l1_height = payload.new_tip().l1_height + 1;

        let terminal_header_complement = payload.sidecar.terminal_header_complement();
        payload.sidecar.terminal_header_complement = TerminalHeaderComplement::new(
            terminal_header_complement.timestamp() + 1,
            *terminal_header_complement.parent_blkid(),
            *terminal_header_complement.body_root(),
            *terminal_header_complement.logs_root(),
        );

        let err = run_proof_pipeline(&mut state, current_l1_height, &payload, asm_manifests_hash)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
    }

    #[test]
    fn test_invalid_ol_l1_progression() {
        let (mut state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let current_l1_height = payload.new_tip().l1_height + 100;

        // Modify the payload to include more L1 blocks after proof generation.
        payload.new_tip.l1_height += 10;
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());

        let err = run_proof_pipeline(&mut state, current_l1_height, &payload, asm_manifests_hash)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
    }
}
