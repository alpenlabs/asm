use bitcoin_bosd::Descriptor;
use ssz::Encode;
use strata_asm_bridge_types::{BRIDGE_GATEWAY_ACCT_SERIAL, OperatorSelection, WithdrawalIntent};
use strata_asm_checkpoint_types::{
    CheckpointClaim, CheckpointPayload, CheckpointSidecar, CheckpointTip, L2BlockRange, OLLog,
    SimpleWithdrawalIntentLogData,
};
use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_btc_types::BitcoinAmount;
use strata_crypto::hash;
use strata_identifiers::{Buf32, L1Height};
use strata_predicate::PredicateKey;
use zkaleido_logging as logging;

use crate::errors::{
    CheckpointValidationResult, InvalidCheckpointPayload, InvalidSequencerKey, hex_encode,
};

/// L1 block range of a checkpoint, returned by [`verify_progression`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointL1Range {
    /// Checkpoint covers no new L1 blocks beyond the previous verified tip. The ASM
    /// manifests hash supplied to [`CheckpointState::advance`](crate::CheckpointState::advance)
    /// must be
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
    last_verified_tip: &CheckpointTip,
    new_tip: &CheckpointTip,
    current_l1_height: L1Height,
) -> CheckpointValidationResult<CheckpointL1Range> {
    // Validate epoch progression: each checkpoint must advance the epoch by exactly 1.
    let expected_epoch = last_verified_tip
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

    let l1_height_covered_in_last_checkpoint = last_verified_tip.l1_height();
    let l1_height_covered_in_new_checkpoint = new_tip.l1_height();

    // Validate L1 progression: checkpoint must cover blocks strictly below the current L1
    // tip — the checkpoint transaction itself is contained in the L1 block at
    // `current_l1_height`, so it can only reference earlier blocks.
    //
    // This comparison must stay strict. The ASM only holds manifests for heights below
    // the block it is processing, so a checkpoint covering its own block would need a
    // manifest that pre-processing cannot request and that the handler then panics on,
    // stranding that L1 block forever.
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
    let prev_slot = last_verified_tip.l2_commitment().slot();
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
/// Reconstructs the full [`CheckpointClaim`] from the last verified tip, the payload's
/// new tip, the sidecar fields, and the precomputed manifest hash, then runs the
/// checkpoint predicate against it.
pub(crate) fn verify_proof(
    predicate: &PredicateKey,
    last_verified_tip: &CheckpointTip,
    payload: &CheckpointPayload,
    asm_manifests_hash: AsmManifestRangeHash,
) -> CheckpointValidationResult<()> {
    let claim = construct_full_claim(
        last_verified_tip,
        payload.new_tip(),
        payload.sidecar(),
        asm_manifests_hash,
    )?;

    predicate
        .verify_claim_witness(&claim.as_ssz_bytes(), payload.proof())
        .map_err(InvalidCheckpointPayload::CheckpointPredicateVerification)?;

    Ok(())
}

/// Verifies that the envelope pubkey is the sequencer's key.
///
/// Uses the SPS-51 envelope trick: the envelope container commits to an initial pubkey that
/// controls the spend, and the ASM treats the script-spend signature as transitively signing
/// the envelope contents. Bitcoin consensus already verified that signature, so matching the
/// pubkey is all that is left to check.
///
/// `envelope_pubkey` is whatever the leaf script pushed, so its length is not known to be 32
/// here. The comparison rejects a wrong length along with a wrong key.
pub fn verify_sequencer_key(
    sequencer_key: &Buf32,
    envelope_pubkey: &[u8],
) -> CheckpointValidationResult<()> {
    if envelope_pubkey != sequencer_key.as_ref() {
        return Err(InvalidSequencerKey::PubkeyMismatch {
            expected: *sequencer_key,
            actual: envelope_pubkey.to_vec(),
        }
        .into());
    }

    Ok(())
}

/// Constructs a complete checkpoint claim for verification by combining the last verified
/// tip state with the new checkpoint payload.
fn construct_full_claim(
    last_verified_tip: &CheckpointTip,
    new_tip: &CheckpointTip,
    sidecar: &CheckpointSidecar,
    asm_manifests_hash: AsmManifestRangeHash,
) -> CheckpointValidationResult<CheckpointClaim> {
    let l2_range = L2BlockRange::new(*last_verified_tip.l2_commitment(), new_tip.l2_commitment);

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
                logging::trace!(
                    account = %log.account_serial(),
                    error = ?e,
                    "skipping non-withdrawal-intent OL log"
                );
                continue;
            }
        };

        // Parse destination descriptor; return error on malformed descriptors
        let destination = match Descriptor::from_bytes(withdrawal_data.dest()) {
            Ok(destination) => destination,
            Err(e) => {
                // CRITICAL: User funds are destroyed on L2 but cannot be withdrawn on L1.
                // Since the extraction is done after the proof verification, this should have been
                // a proper descriptor. Log the raw intent so the lost withdrawal can be traced.
                logging::error!(
                    amount_sat = withdrawal_data.amt(),
                    dest = %hex_encode(withdrawal_data.dest()),
                    operator = withdrawal_data.selected_operator,
                    error = %e,
                    "failed to parse withdrawal destination descriptor; user funds unrecoverable"
                );
                return Err(InvalidCheckpointPayload::MalformedWithdrawalDestDesc.into());
            }
        };

        let selected_operator = OperatorSelection::from_raw(withdrawal_data.selected_operator);
        let sats = withdrawal_data.amt();
        let amount = BitcoinAmount::try_from(sats)
            .map_err(|_| InvalidCheckpointPayload::InvalidWithdrawalAmount { sats })?;
        let withdraw_output = WithdrawalIntent::new(destination, amount, selected_operator);
        withdrawal_intents.push(withdraw_output);
    }

    Ok(withdrawal_intents)
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;
    use ssz_types::VariableList;
    use strata_asm_bridge_types::{BRIDGE_GATEWAY_ACCT_SERIAL, WithdrawalIntent};
    use strata_asm_checkpoint_types::{
        CheckpointInitConfig, CheckpointPayload, CheckpointTip, OLLog, PendingPredicateTransition,
        SimpleWithdrawalIntentLogData, TerminalHeaderComplement,
    };
    use strata_asm_manifest_types::AsmManifestRangeHash;
    use strata_btc_types::BitcoinAmount;
    use strata_identifiers::AccountSerial;
    use strata_msg_fmt::{Msg, OwnedMsg};
    use strata_predicate::PredicateKey;
    use strata_test_utils_checkpoint::CheckpointTestHarness;

    use crate::{
        CheckpointState, PredicateSelection,
        errors::{
            CheckpointValidationError, CheckpointValidationResult, InvalidCheckpointPayload,
            InvalidSequencerKey,
        },
        verification::{
            CheckpointL1Range, extract_withdrawal_intents, verify_progression, verify_sequencer_key,
        },
    };

    fn test_setup() -> (CheckpointState, CheckpointTestHarness) {
        let harness = CheckpointTestHarness::new_random();
        let state = CheckpointState::new(
            harness.sequencer_key(),
            harness.checkpoint_predicate(),
            *harness.verified_tip(),
        );
        (state, harness)
    }

    /// Drives the full progression + selection + proof pipeline with a precomputed manifest
    /// hash, in the same order the subprotocol handler does.
    /// Skips sequencer authentication, which has its own dedicated tests.
    fn run_proof_pipeline(
        state: &mut CheckpointState,
        current_l1_height: u32,
        payload: &CheckpointPayload,
        asm_manifests_hash: AsmManifestRangeHash,
    ) -> CheckpointValidationResult<(Vec<WithdrawalIntent>, bool)> {
        let coverage =
            verify_progression(state.verified_tip(), payload.new_tip(), current_l1_height)?;
        let selection = state.select_predicate(&coverage)?;
        state.advance(payload, asm_manifests_hash, selection)
    }

    #[test]
    fn test_validate_checkpoint_success() {
        let (mut state, harness) = test_setup();
        let payload = harness.build_payload();
        let new_tip = *payload.new_tip();
        let asm_manifests_hash = harness.gen_asm_manifests_hash(&new_tip);
        let current_l1_height = new_tip.l1_height + 1;

        verify_sequencer_key(state.sequencer_key(), harness.sequencer_pubkey()).expect("auth");
        let res = run_proof_pipeline(&mut state, current_l1_height, &payload, asm_manifests_hash);
        assert!(res.is_ok());
    }

    // --- Sequencer authentication ---

    #[test]
    fn test_wrong_envelope_pubkey() {
        let harness = CheckpointTestHarness::new_random();
        let err = verify_sequencer_key(&harness.sequencer_key(), &[0u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidSequencerKey(
                InvalidSequencerKey::PubkeyMismatch { .. }
            )
        ));
    }

    /// The envelope pubkey is an arbitrary-length script push, so a key of the wrong
    /// length must be rejected rather than compared against a truncated or padded copy.
    /// Bitcoin would already reject an envelope with no pubkey set; this is a railguard
    /// checking the ASM rejects it too.
    #[test]
    fn test_wrong_length_envelope_pubkey_rejected() {
        let harness = CheckpointTestHarness::new_random();
        for pubkey in [[].as_slice(), &[0xab; 31], &[0xab; 33]] {
            let err = verify_sequencer_key(&harness.sequencer_key(), pubkey).unwrap_err();
            assert!(matches!(
                err,
                CheckpointValidationError::InvalidSequencerKey(
                    InvalidSequencerKey::PubkeyMismatch { .. }
                )
            ));
        }
    }

    #[test]
    fn test_matching_envelope_pubkey_accepted() {
        let harness = CheckpointTestHarness::new_random();
        verify_sequencer_key(&harness.sequencer_key(), harness.sequencer_pubkey())
            .expect("the sequencer's own key authenticates");
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

    /// Boundary case for the check above: a checkpoint covering the block that carries
    /// it. Relaxing `>=` to `>` would accept it and strand that L1 block, because the
    /// ASM has no manifest for its own height yet. Keep this test passing.
    #[test]
    fn test_new_tip_at_current_l1_height_is_rejected() {
        let harness = CheckpointTestHarness::new_random();
        let payload = harness.build_payload();
        let current_l1_height = payload.new_tip().l1_height;

        let err = verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointBeyondL1Tip { .. }
            )
        ));
    }

    /// The highest L1 height a checkpoint may cover. Its manifests are the last ones the
    /// ASM can resolve, so this is the case the aux request bound has to admit.
    #[test]
    fn test_new_tip_just_below_current_l1_height_is_accepted() {
        let harness = CheckpointTestHarness::new_random();
        let payload = harness.build_payload();
        let new_height = payload.new_tip().l1_height;
        let current_l1_height = new_height + 1;

        let coverage =
            verify_progression(harness.verified_tip(), payload.new_tip(), current_l1_height)
                .expect("a checkpoint one height below the current block is accepted");
        assert_eq!(
            coverage,
            CheckpointL1Range::Range {
                start_height: harness.verified_tip().l1_height + 1,
                end_height: new_height,
            }
        );
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

    // --- Predicate selection and activation ---

    #[test]
    fn test_select_predicate_for_each_range_branch() {
        let (mut state, harness) = test_setup();
        let boundary = harness.verified_tip().l1_height() + 20;
        state.queue_predicate_transition(PendingPredicateTransition::new(
            PredicateKey::always_accept(),
            boundary,
        ));

        assert_eq!(
            state
                .select_predicate(&CheckpointL1Range::Range {
                    start_height: boundary - 5,
                    end_height: boundary,
                })
                .unwrap(),
            PredicateSelection::Active
        );
        assert_eq!(
            state
                .select_predicate(&CheckpointL1Range::Range {
                    start_height: boundary + 1,
                    end_height: boundary + 5,
                })
                .unwrap(),
            PredicateSelection::Pending
        );

        let err = state
            .select_predicate(&CheckpointL1Range::Range {
                start_height: boundary,
                end_height: boundary + 1,
            })
            .unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::RangeStraddlesPredicateBoundary {
                    start,
                    end,
                    boundary: reported,
                }
            ) if start == boundary && end == boundary + 1 && reported == boundary
        ));
    }

    #[test]
    fn test_empty_range_selects_by_verified_tip() {
        let boundary = 100;
        for (verified_height, expected) in [
            (boundary - 1, PredicateSelection::Active),
            (boundary, PredicateSelection::Pending),
            (boundary + 1, PredicateSelection::Pending),
        ] {
            let (mut state, harness) = test_setup();
            state.verified_tip.l1_height = verified_height;
            state.queue_predicate_transition(PendingPredicateTransition::new(
                PredicateKey::always_accept(),
                boundary,
            ));
            assert_eq!(
                state.select_predicate(&CheckpointL1Range::Empty).unwrap(),
                expected,
                "unexpected selection for verified height {verified_height}"
            );

            // Keep the harness alive through the assertion so its randomly generated
            // predicates cannot be optimized out of the state setup.
            assert_eq!(state.sequencer_key(), &harness.sequencer_key());
        }
    }

    #[test]
    fn test_empty_range_at_u32_max_selects_pending_without_successor_arithmetic() {
        let (mut state, _) = test_setup();
        state.verified_tip.l1_height = u32::MAX;
        state.queue_predicate_transition(PendingPredicateTransition::new(
            PredicateKey::always_accept(),
            u32::MAX,
        ));

        assert_eq!(
            state.select_predicate(&CheckpointL1Range::Empty).unwrap(),
            PredicateSelection::Pending
        );
    }

    /// A checkpoint accepted under the pending key promotes it and empties the slot.
    #[test]
    fn test_acceptance_under_pending_key_promotes_and_clears_slot() {
        let (mut state, mut harness) = test_setup();
        let signer = CheckpointTestHarness::mint_checkpoint_signer();
        let active_predicate = state.checkpoint_predicate().clone();
        let boundary = harness.verified_tip().l1_height() + 10;
        let mut baseline = *harness.verified_tip();
        baseline.l1_height = boundary;
        harness.update_verified_tip(baseline);
        state.verified_tip = baseline;
        state.queue_predicate_transition(PendingPredicateTransition::new(
            signer.predicate(),
            boundary,
        ));
        assert_ne!(active_predicate, signer.predicate());

        let new_tip = CheckpointTip {
            l1_height: boundary + 5,
            ..harness.gen_new_tip()
        };
        let payload = harness.build_payload_with_tip_and_signer(new_tip, &signer);
        let hash = harness.gen_asm_manifests_hash(&new_tip);
        let (_, promoted) = run_proof_pipeline(&mut state, boundary + 6, &payload, hash).unwrap();

        assert!(promoted);
        assert_eq!(state.checkpoint_predicate(), &signer.predicate());
        assert!(state.pending_transition().is_none());
    }

    #[test]
    fn test_selected_predicate_failure_leaves_state_unchanged() {
        let (mut state, mut harness) = test_setup();
        let signer = CheckpointTestHarness::mint_checkpoint_signer();
        let boundary = harness.verified_tip().l1_height() + 10;
        let mut baseline = *harness.verified_tip();
        baseline.l1_height = boundary;
        harness.update_verified_tip(baseline);
        state.verified_tip = baseline;
        state.record_deposit(
            BitcoinAmount::try_from(100_000)
                .expect("test amount must be within the Bitcoin money supply"),
        );
        state.queue_predicate_transition(PendingPredicateTransition::new(
            signer.predicate(),
            boundary,
        ));
        let previous_tip = *state.verified_tip();
        let previous_deposits = state.available_deposit_sum();
        let previous_transition = state.pending_transition().cloned();

        let new_tip = CheckpointTip {
            l1_height: boundary + 1,
            ..harness.gen_new_tip()
        };
        let payload = harness.build_payload_with_tip(new_tip);
        let hash = harness.gen_asm_manifests_hash(&new_tip);
        let err = run_proof_pipeline(&mut state, boundary + 2, &payload, hash).unwrap_err();

        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::CheckpointPredicateVerification(_)
            )
        ));
        assert_eq!(state.verified_tip(), &previous_tip);
        assert_eq!(state.available_deposit_sum(), previous_deposits);
        assert_eq!(state.pending_transition().cloned(), previous_transition);
    }

    #[test]
    fn test_window_shortening_range_is_rejected_as_straddle() {
        let (mut state, harness) = test_setup();
        let boundary = harness.verified_tip().l1_height() + 101;
        state.queue_predicate_transition(PendingPredicateTransition::new(
            PredicateKey::always_accept(),
            boundary,
        ));
        let new_tip = CheckpointTip {
            l1_height: boundary + 1,
            ..harness.gen_new_tip()
        };
        let payload = harness.build_payload_with_tip(new_tip);
        let hash = harness.gen_asm_manifests_hash(&new_tip);

        let err = run_proof_pipeline(&mut state, boundary + 2, &payload, hash).unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::RangeStraddlesPredicateBoundary {
                    start,
                    end,
                    boundary: reported,
                }
            ) if start == boundary - 100 && end == boundary + 1 && reported == boundary
        ));
    }

    #[test]
    fn test_late_pre_boundary_checkpoint_uses_active_predicate() {
        let (mut state, harness) = test_setup();
        let boundary = harness.verified_tip().l1_height() + 20;
        let transition = PendingPredicateTransition::new(PredicateKey::never_accept(), boundary);
        state.queue_predicate_transition(transition.clone());
        let new_tip = CheckpointTip {
            l1_height: boundary - 1,
            ..harness.gen_new_tip()
        };
        let payload = harness.build_payload_with_tip(new_tip);
        let hash = harness.gen_asm_manifests_hash(&new_tip);

        let (_, promoted) = run_proof_pipeline(&mut state, boundary + 2, &payload, hash).unwrap();
        assert!(!promoted);
        assert_eq!(state.verified_tip(), &new_tip);
        assert_eq!(state.pending_transition(), Some(&transition));
    }

    #[test]
    fn test_init_starts_without_a_pending_transition() {
        let harness = CheckpointTestHarness::new_random();
        let config = CheckpointInitConfig {
            sequencer_key: harness.sequencer_key(),
            checkpoint_predicate: harness.checkpoint_predicate(),
            genesis_l1_height: harness.genesis_l1_height(),
            genesis_ol_blkid: *harness.verified_tip().l2_commitment().blkid(),
        };

        let state = CheckpointState::init(config);

        assert_eq!(
            state.checkpoint_predicate(),
            &harness.checkpoint_predicate()
        );
        assert!(state.pending_transition().is_none());
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
        assert_eq!(
            outputs[0].amt(),
            BitcoinAmount::try_from(withdrawal.amt())
                .expect("test amount must be within the Bitcoin money supply")
        );
    }

    #[test]
    fn test_extract_rejects_amount_above_money_supply() {
        const OVER_MAX_MONEY_SATS: u64 = 2_100_000_000_000_001;

        let dest = Descriptor::new_p2wpkh(&[0x14; 20]).to_bytes();
        let withdrawal = SimpleWithdrawalIntentLogData::new(OVER_MAX_MONEY_SATS, dest, 0)
            .expect("withdrawal intent creation should not fail");
        let log = OLLog::from_log(BRIDGE_GATEWAY_ACCT_SERIAL, &withdrawal).unwrap();

        let err = extract_withdrawal_intents(&[log]).unwrap_err();
        assert!(matches!(
            err,
            CheckpointValidationError::InvalidPayload(
                InvalidCheckpointPayload::InvalidWithdrawalAmount { sats }
            ) if sats == OVER_MAX_MONEY_SATS
        ));
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
