//! Test utilities and proptest strategies for checkpoint types.

use proptest::prelude::*;
use strata_asm_manifest_types::AsmManifestRangeHash;
use strata_identifiers::{
    AccountSerial, Buf32, OLBlockCommitment,
    test_utils::{
        buf32_strategy, epoch_strategy, fixed_bytes_32_strategy, ol_block_commitment_strategy,
        ol_block_id_strategy,
    },
};

use crate::{
    CheckpointClaim, CheckpointPayload, CheckpointSidecar, CheckpointTip, L2BlockRange,
    MAX_LOG_PAYLOAD_LEN, MAX_OL_LOGS_PER_CHECKPOINT, MAX_PROOF_LEN, OL_DA_DIFF_MAX_SIZE, OLLog,
    TerminalHeaderComplement,
};

/// Creates a minimal [`CheckpointPayload`] for the given epoch using validated constructors.
pub fn create_test_checkpoint_payload(epoch: u32) -> CheckpointPayload {
    let tip = CheckpointTip::new(epoch, 200, OLBlockCommitment::new(1, Buf32::zero().into()));
    let sidecar = CheckpointSidecar::new(
        vec![2; 100],
        vec![],
        TerminalHeaderComplement::new(0, Buf32::zero().into(), Buf32::zero(), Buf32::zero()),
    )
    .expect("test sidecar is within size limits");

    CheckpointPayload::new(tip, sidecar, vec![0]).expect("test payload is within size limits")
}

/// Strategy for generating random [`CheckpointTip`] values.
pub fn checkpoint_tip_strategy() -> impl Strategy<Value = CheckpointTip> {
    (
        epoch_strategy(),
        any::<u32>(),
        ol_block_commitment_strategy(),
    )
        .prop_map(|(epoch, l1_height, l2_commitment)| {
            CheckpointTip::new(epoch, l1_height, l2_commitment)
        })
}

/// Strategy for generating state diff bytes spanning the full valid size range.
///
/// The state diff is an opaque blob bounded only by [`OL_DA_DIFF_MAX_SIZE`], the cap
/// [`CheckpointSidecar::new`] enforces; on this repo the implicit Bitcoin transaction size limit
/// keeps real payloads well under it, but the type accepts anything up to the cap.
fn state_diff_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=OL_DA_DIFF_MAX_SIZE as usize)
}

/// Strategy for generating proof bytes spanning the full valid size range.
///
/// Bounded by [`MAX_PROOF_LEN`], the cap [`CheckpointPayload::new`] enforces.
fn proof_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=MAX_PROOF_LEN as usize)
}

/// Upper bound on the summed log payload a single draw will materialize.
///
/// This is purely a proptest-tractability knob: the type imposes no total-log-payload cap, so
/// the schema caps alone ([`MAX_OL_LOGS_PER_CHECKPOINT`] logs × [`MAX_LOG_PAYLOAD_LEN`] bytes each)
/// would let one draw allocate tens of MiB. Overall checkpoint size is bounded implicitly by the
/// Bitcoin transaction limit and checked downstream at construction, not by this crate. Reuse
/// [`OL_DA_DIFF_MAX_SIZE`] as a representative ceiling rather than inventing another figure.
const GENERATED_LOG_PAYLOAD_BUDGET: usize = OL_DA_DIFF_MAX_SIZE as usize;

/// Strategy for candidate OL-log payload *sizes*, bounded by the two schema caps
/// [`CheckpointSidecar::new`] enforces: at most [`MAX_OL_LOGS_PER_CHECKPOINT`] logs, each payload
/// at most [`MAX_LOG_PAYLOAD_LEN`] bytes (enforced by [`OLLog`]). A large `ol_state_diff` reduces
/// neither.
///
/// Sizes are returned rather than materialized logs so [`checkpoint_sidecar_strategy`] can apply
/// [`GENERATED_LOG_PAYLOAD_BUDGET`] before allocating any payload bytes — the schema caps alone
/// would otherwise let one draw materialize tens of MiB.
fn ol_log_sizes_strategy() -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(
        0..=MAX_LOG_PAYLOAD_LEN as usize,
        0..=MAX_OL_LOGS_PER_CHECKPOINT as usize,
    )
}

/// Builds the OL logs for a sidecar from candidate payload sizes, keeping the longest prefix whose
/// cumulative payload fits [`GENERATED_LOG_PAYLOAD_BUDGET`].
///
/// The budget is only a generation guard, not a validity bound (the type imposes no total-log cap);
/// truncating before materializing keeps a draw bounded while still exercising both regimes — large
/// payloads fill the budget after a few logs, near-empty payloads extend the prefix toward the
/// [`MAX_OL_LOGS_PER_CHECKPOINT`] count cap.
fn build_bounded_ol_logs(sizes: Vec<usize>) -> Vec<OLLog> {
    let mut total = 0usize;
    sizes
        .into_iter()
        .enumerate()
        .map_while(|(index, size)| {
            total += size;
            if total > GENERATED_LOG_PAYLOAD_BUDGET {
                return None;
            }
            // Vary the account serial and payload bytes per log so the round-trip exercises real
            // content rather than a single repeated value.
            let account_serial = AccountSerial::from(index as u32);
            let payload = (0..size).map(|byte| (index + byte) as u8).collect();
            Some(OLLog::new(account_serial, payload))
        })
        .collect()
}

/// Strategy for generating random [`crate::TerminalHeaderComplement`] values.
fn terminal_header_complement_strategy() -> impl Strategy<Value = crate::TerminalHeaderComplement> {
    (
        any::<u64>(),
        ol_block_id_strategy(),
        buf32_strategy(),
        buf32_strategy(),
    )
        .prop_map(|(timestamp, parent_blkid, body_root, logs_root)| {
            crate::TerminalHeaderComplement::new(timestamp, parent_blkid, body_root, logs_root)
        })
}

/// Strategy for generating random [`CheckpointSidecar`] values.
pub fn checkpoint_sidecar_strategy() -> impl Strategy<Value = CheckpointSidecar> {
    (
        state_diff_strategy(),
        ol_log_sizes_strategy(),
        terminal_header_complement_strategy(),
    )
        .prop_map(|(state_diff, log_sizes, terminal_header_complement)| {
            // Limit the logs to the generation budget here, where the whole sidecar is assembled.
            let ol_logs = build_bounded_ol_logs(log_sizes);
            CheckpointSidecar::new(state_diff, ol_logs, terminal_header_complement)
                .expect("schema caps satisfied by construction")
        })
}

/// Strategy for generating random [`CheckpointPayload`] values.
pub fn checkpoint_payload_strategy() -> impl Strategy<Value = CheckpointPayload> {
    (
        checkpoint_tip_strategy(),
        checkpoint_sidecar_strategy(),
        proof_strategy(),
    )
        .prop_map(|(tip, sidecar, proof)| {
            CheckpointPayload::new(tip, sidecar, proof).expect("valid payload")
        })
}

/// Strategy for generating random [`L2BlockRange`] values.
pub fn l2_block_range_strategy() -> impl Strategy<Value = L2BlockRange> {
    (
        ol_block_commitment_strategy(),
        ol_block_commitment_strategy(),
    )
        .prop_map(|(start, end)| L2BlockRange::new(start, end))
}

/// Strategy for generating random [`CheckpointClaim`] values.
pub fn checkpoint_claim_strategy() -> impl Strategy<Value = CheckpointClaim> {
    (
        epoch_strategy(),
        l2_block_range_strategy(),
        buf32_strategy(),
        fixed_bytes_32_strategy(),
        fixed_bytes_32_strategy(),
        fixed_bytes_32_strategy(),
    )
        .prop_map(
            |(
                epoch,
                l2_range,
                asm_manifests_hash_buf,
                state_diff_hash,
                ol_logs_hash,
                terminal_header_complement_hash,
            )| {
                CheckpointClaim::new(
                    epoch,
                    l2_range,
                    AsmManifestRangeHash::from(asm_manifests_hash_buf),
                    state_diff_hash,
                    ol_logs_hash,
                    terminal_header_complement_hash,
                )
            },
        )
}
