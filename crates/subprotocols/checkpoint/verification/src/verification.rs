use bitcoin_bosd::Descriptor;
use ssz::Encode;
use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_asm_proto_bridge_v1_types::{
    BRIDGE_GATEWAY_ACCT_SERIAL, OperatorSelection, WithdrawOutput,
};
use strata_asm_proto_checkpoint_types::{
    CheckpointClaim, CheckpointPayload, CheckpointSidecar, CheckpointTip, L2BlockRange, OLLog,
    SimpleWithdrawalIntentLogData,
};
use strata_codec::decode_buf_exact;
use strata_crypto::hash;
use strata_identifiers::L1Height;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido_logging as logging;

use crate::{
    errors::{CheckpointValidationResult, InvalidCheckpointPayload, InvalidSequencerPredicate},
    state::{CheckpointState, VerifiedWithdrawals},
};

/// Successful result of checkpoint validation.
///
/// Contains the extracted withdrawal intents and a [`VerifiedWithdrawals`] token that must be
/// passed to the checkpoint state's deduction method to apply the fund update.
#[derive(Debug)]
pub struct ValidatedCheckpointWithdrawals {
    /// Withdrawal intents extracted from the checkpoint's OL logs.
    pub withdrawal_intents: Vec<(WithdrawOutput, OperatorSelection)>,
    /// Token proving that the withdrawals have been verified against available funds.
    pub verified_withdrawals: VerifiedWithdrawals,
}

/// Token returned by [`verify_progression`] identifying the L1 block range the checkpoint
/// covers.
///
/// The contained `start_height` and `end_height` (inclusive) are the heights of the L1
/// blocks whose ASM manifests must be hashed and passed back to
/// [`verify_proof_and_extract_withdrawal_intents`]. Has no public constructor: instances
/// can only be obtained from [`verify_progression`], which enforces at the type level
/// that the range has been validated before manifest hashes are consumed.
#[derive(Debug)]
pub struct ValidatedL1Range {
    start_height: u32,
    end_height: u32,
}

impl ValidatedL1Range {
    /// First L1 block height covered by the new checkpoint (inclusive).
    pub fn start_height(&self) -> u32 {
        self.start_height
    }

    /// Last L1 block height covered by the new checkpoint (inclusive).
    pub fn end_height(&self) -> u32 {
        self.end_height
    }
}

/// Phase 1 of checkpoint validation: validates the checkpoint's range against progression
/// rules — epoch advances by exactly 1, L1 height does not regress and stays strictly
/// below the current L1 tip, and L2 slot advances.
///
/// On success, returns a [`ValidatedL1Range`] identifying the L1 block range whose ASM
/// manifests the caller must hash for phase 2. The caller resolves the range to manifest
/// hashes and passes them — alongside the token — to
/// [`verify_proof_and_extract_withdrawal_intents`], which performs sequencer
/// authentication and proof verification.
///
/// This function is pure — it does not mutate state.
pub fn verify_progression(
    verified_tip: &CheckpointTip,
    new_tip: &CheckpointTip,
    current_l1_height: L1Height,
) -> CheckpointValidationResult<ValidatedL1Range> {
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

    Ok(ValidatedL1Range {
        start_height: l1_height_covered_in_last_checkpoint + 1,
        end_height: l1_height_covered_in_new_checkpoint,
    })
}

/// Phase 2 of checkpoint validation: verifies the ZK proof against the precomputed ASM
/// manifests hash and extracts withdrawal intents.
///
/// The [`ValidatedL1Range`] token must come from a successful [`verify_progression`] call
/// against the same checkpoint, ensuring the range was validated before manifest hashes
/// were resolved. The token is consumed.
///
/// Envelope authentication via [`verify_sequencer_predicate`] is the caller's
/// responsibility — typically gated before this call.
///
/// This function is pure — it does not mutate state.
pub fn verify_proof_and_extract_withdrawal_intents(
    state: &CheckpointState,
    payload: &CheckpointPayload,
    _validated_range: ValidatedL1Range,
    asm_manifests_hash: AsmManifestRangeHash,
) -> CheckpointValidationResult<ValidatedCheckpointWithdrawals> {
    // Reconstruct the full claim from the verified tip, the new tip, the sidecar, and
    // the precomputed ASM manifests hash, then verify the proof against it.
    let claim = construct_full_claim(
        &state.verified_tip,
        payload.new_tip(),
        payload.sidecar(),
        asm_manifests_hash,
    )?;

    state
        .checkpoint_predicate()
        .verify_claim_witness(&claim.as_ssz_bytes(), payload.proof())
        .map_err(InvalidCheckpointPayload::CheckpointPredicateVerification)?;

    // Extract withdrawal intents from the OL logs and verify available funds can cover
    // them with exact-denomination UTXO matches.
    let withdrawal_intents = extract_and_validate_withdrawal_intents(payload.sidecar().ol_logs())?;

    let withdraw_outputs: Vec<_> = withdrawal_intents.iter().map(|(w, _)| w.clone()).collect();
    let verified_withdrawals = state.verify_can_honor_withdrawals(&withdraw_outputs)?;

    Ok(ValidatedCheckpointWithdrawals {
        withdrawal_intents,
        verified_withdrawals,
    })
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
/// destination descriptors can be parsed, and returns the extracted withdrawal outputs.
fn extract_and_validate_withdrawal_intents(
    logs: &[OLLog],
) -> CheckpointValidationResult<Vec<(WithdrawOutput, OperatorSelection)>> {
    let mut withdrawal_intents = Vec::new();

    for log in logs
        .iter()
        .filter(|l| l.account_serial() == BRIDGE_GATEWAY_ACCT_SERIAL)
    {
        // Attempt to decode as withdrawal intent log data
        // Logs from this account may have other formats, so skip if decoding fails
        let Ok(withdrawal_data) = decode_buf_exact::<SimpleWithdrawalIntentLogData>(log.payload())
        else {
            logging::debug!("Skipping log that is not a withdrawal intent");
            continue;
        };

        // Parse destination descriptor; return error on malformed descriptors
        let Ok(destination) = Descriptor::from_bytes(withdrawal_data.dest()) else {
            // CRITICAL: User funds are destroyed on L2 but cannot be withdrawn on L1.
            // Since the extraction is done after the proof verification, this should have been a
            // proper descriptor.
            logging::error!("Failed to parse withdrawal destination descriptor");
            return Err(InvalidCheckpointPayload::MalformedWithdrawalDestDesc.into());
        };

        let selected_operator = OperatorSelection::from_raw(withdrawal_data.selected_operator);
        let withdraw_output = WithdrawOutput::new(destination, withdrawal_data.amt().into());
        withdrawal_intents.push((withdraw_output, selected_operator));
    }

    Ok(withdrawal_intents)
}

#[cfg(test)]
mod tests {
    use ssz_types::VariableList;
    use strata_asm_manifest_types::AsmManifestRangeHash;
    use strata_asm_proto_checkpoint_types::{CheckpointPayload, OLLog, TerminalHeaderComplement};
    use strata_identifiers::AccountSerial;
    use strata_predicate::PredicateKey;
    use strata_test_utils_checkpoint::CheckpointTestHarness;

    use crate::{
        errors::{
            CheckpointValidationError, CheckpointValidationResult, InvalidCheckpointPayload,
            InvalidSequencerPredicate,
        },
        state::CheckpointState,
        verification::{
            ValidatedCheckpointWithdrawals, verify_progression,
            verify_proof_and_extract_withdrawal_intents, verify_sequencer_predicate,
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

    /// Drives progression + proof phases with a precomputed manifest hash. Used by
    /// proof-phase tests that need a real `ValidatedL1Range` token to reach phase 2.
    /// Skips sequencer authentication, which has its own dedicated tests.
    fn run_proof_pipeline(
        state: &CheckpointState,
        current_l1_height: u32,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
    ) -> CheckpointValidationResult<ValidatedCheckpointWithdrawals> {
        let range = verify_progression(state.verified_tip(), payload.new_tip(), current_l1_height)?;
        verify_proof_and_extract_withdrawal_intents(state, payload, range, asm_manifests_hash)
    }

    #[test]
    fn test_validate_checkpoint_success() {
        let (state, harness) = test_setup();
        let payload = harness.build_payload();
        let new_tip = *payload.new_tip();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(&new_tip);
        let current_l1_height = new_tip.l1_height + 1;

        verify_sequencer_predicate(state.sequencer_predicate(), harness.sequencer_pubkey())
            .expect("auth");
        let res = run_proof_pipeline(&state, current_l1_height, &payload, asm_manifests_hash);
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

    // --- Progression (phase 1) ---

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

        let res = verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height);
        assert!(res.is_ok());
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

    // --- Proof verification + withdrawal extraction (phase 2) ---

    #[test]
    fn test_invalid_state_diff() {
        let (state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());
        let current_l1_height = payload.new_tip().l1_height + 1;

        // Modify the payload to include invalid state diff after proof generation.
        payload.sidecar.ol_state_diff = vec![99u8; 88].try_into().unwrap();

        let err = run_proof_pipeline(&state, current_l1_height, &payload, asm_manifests_hash)
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
        let (state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());
        let current_l1_height = payload.new_tip().l1_height + 1;

        // Modify the payload to include OL Logs that wasn't covered by the proof.
        let dummy_log = OLLog::new(AccountSerial::zero(), Vec::new());
        payload.sidecar.ol_logs = VariableList::new(vec![dummy_log]).unwrap();

        let err = run_proof_pipeline(&state, current_l1_height, &payload, asm_manifests_hash)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
    }

    #[test]
    fn test_invalid_terminal_header_complement() {
        let (state, harness) = test_setup();
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

        let err = run_proof_pipeline(&state, current_l1_height, &payload, asm_manifests_hash)
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
        let (state, harness) = test_setup();
        let mut payload = harness.build_payload();
        let current_l1_height = payload.new_tip().l1_height + 100;

        // Modify the payload to include more L1 blocks after proof generation.
        payload.new_tip.l1_height += 10;
        let asm_manifests_hash = harness.gen_asm_manifests_hash(payload.new_tip());

        let err = run_proof_pipeline(&state, current_l1_height, &payload, asm_manifests_hash)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
    }
}
