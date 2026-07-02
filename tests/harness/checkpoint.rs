//! Checkpoint subprotocol test utilities
//!
//! Provides helpers for testing checkpoint subprotocol state and inter-subprotocol messaging.
//!
//! # Example
//!
//! ```ignore
//! use harness::test_harness::AsmTestHarnessBuilder;
//! use harness::checkpoint::CheckpointExt;
//!
//! let harness = AsmTestHarnessBuilder::default().build().await?;
//! let state = harness.checkpoint_state()?;
//! ```

use std::future::Future;

use bitcoin::{key::UntweakedKeypair, secp256k1::Secp256k1, BlockHash, Transaction};
use bitcoin_bosd::Descriptor;
use strata_asm_common::{AnchorState, Subprotocol};
use strata_asm_logs::CheckpointTipUpdate;
use strata_asm_manifest_types::{AsmLog, AsmManifestHash};
use strata_asm_params::CheckpointInitConfig;
use strata_asm_proto_bridge_v1_types::{OperatorSelection, BRIDGE_GATEWAY_ACCT_SERIAL};
use strata_asm_proto_checkpoint::{CheckpointState, CheckpointSubprotocol};
use strata_asm_proto_checkpoint_types::{CheckpointTip, OLLog, SimpleWithdrawalIntentLogData};
use strata_codec::encode_to_vec;
use strata_codec_utils::CodecSsz;
use strata_identifiers::{OLBlockCommitment, OLBlockId};
use strata_l1_txfmt::TagData;
use strata_test_utils_arb::ArbitraryGenerator;
use strata_test_utils_checkpoint::CheckpointTestHarness;

use super::test_harness::AsmTestHarness;

/// Checkpoint subprotocol ID per SPS-50.
pub const SUBPROTOCOL_ID: u8 = 1;

/// Extract checkpoint subprotocol state from AnchorState.
pub fn extract_checkpoint_state(anchor_state: &AnchorState) -> anyhow::Result<CheckpointState> {
    let section = anchor_state
        .find_section(CheckpointSubprotocol::ID)
        .ok_or_else(|| anyhow::anyhow!("Checkpoint section not found"))?;
    let checkpoint_state = section.try_to_state::<CheckpointSubprotocol>()?;
    Ok(checkpoint_state)
}

// ============================================================================
// Checkpoint Extension Trait
// ============================================================================

/// Extension trait for checkpoint subprotocol operations on the test harness.
///
/// This trait provides checkpoint-specific convenience methods while keeping
/// the core harness infrastructure-focused.
pub trait CheckpointExt {
    /// Get checkpoint subprotocol state.
    fn checkpoint_state(&self) -> anyhow::Result<CheckpointState>;

    /// Get the `CheckpointTipUpdate` log tips emitted while processing the latest block.
    ///
    /// The checkpoint subprotocol emits exactly one such log per accepted checkpoint, so the
    /// length of the returned vec is the number of checkpoints accepted in that block.
    fn checkpoint_tip_update_logs(&self) -> anyhow::Result<Vec<CheckpointTip>>;

    /// Submit a checkpoint carrying withdrawal intents for the given amounts.
    ///
    /// Builds a valid checkpoint payload whose OL logs encode one withdrawal intent per amount
    /// (each with no specific operator selection), signs it, and submits it as an SPS-50
    /// envelope transaction. Advances the checkpoint harness's verified tip on success.
    fn submit_checkpoint_with_withdrawals(
        &self,
        checkpoint_harness: &mut CheckpointTestHarness,
        withdrawal_amounts: &[u64],
    ) -> impl Future<Output = anyhow::Result<BlockHash>>;

    /// Submit a checkpoint with withdrawal intents that pin per-intent operator selection.
    ///
    /// Like [`submit_checkpoint_with_withdrawals`](Self::submit_checkpoint_with_withdrawals),
    /// but each intent is `(amount, operator_selection)` so callers can request a specific
    /// operator or fall back to the random "any" sentinel.
    fn submit_checkpoint_with_withdrawal_intents(
        &self,
        checkpoint_harness: &mut CheckpointTestHarness,
        intents: &[(u64, OperatorSelection)],
    ) -> impl Future<Output = anyhow::Result<BlockHash>>;
}

impl CheckpointExt for AsmTestHarness {
    fn checkpoint_state(&self) -> anyhow::Result<CheckpointState> {
        let (_, asm_state) = self
            .get_latest_asm_state()?
            .ok_or_else(|| anyhow::anyhow!("No ASM state available"))?;
        extract_checkpoint_state(&asm_state)
    }

    fn checkpoint_tip_update_logs(&self) -> anyhow::Result<Vec<CheckpointTip>> {
        let (block, _) = self
            .get_latest_asm_state()?
            .ok_or_else(|| anyhow::anyhow!("No ASM state available"))?;
        self.get_logs_at(&block)
            .iter()
            .filter(|entry| entry.ty() == Some(CheckpointTipUpdate::TY))
            .map(|entry| {
                entry
                    .try_into_log::<CheckpointTipUpdate>()
                    .map(|log| *log.tip())
                    .map_err(|e| anyhow::anyhow!("failed to decode CheckpointTipUpdate log: {e:?}"))
            })
            .collect()
    }

    async fn submit_checkpoint_with_withdrawals(
        &self,
        checkpoint_harness: &mut CheckpointTestHarness,
        withdrawal_amounts: &[u64],
    ) -> anyhow::Result<BlockHash> {
        let intents: Vec<(u64, OperatorSelection)> = withdrawal_amounts
            .iter()
            .map(|&amt| (amt, OperatorSelection::any()))
            .collect();
        self.submit_checkpoint_with_withdrawal_intents(checkpoint_harness, &intents)
            .await
    }

    async fn submit_checkpoint_with_withdrawal_intents(
        &self,
        checkpoint_harness: &mut CheckpointTestHarness,
        intents: &[(u64, OperatorSelection)],
    ) -> anyhow::Result<BlockHash> {
        let ol_logs = build_withdrawal_ol_logs(intents);
        let (tx, new_tip) = self
            .build_checkpoint_tx(checkpoint_harness, ol_logs)
            .await?;
        let block_hash = self.submit_and_mine_tx(&tx).await?;
        checkpoint_harness.update_verified_tip(new_tip);
        Ok(block_hash)
    }
}

/// Builds OL logs encoding withdrawal intents for the given (amount, selection) pairs.
///
/// Each withdrawal intent is a [`SimpleWithdrawalIntentLogData`] wrapped in a msg-fmt envelope
/// (via [`OLLog::from_log`]) emitted from the bridge gateway account.
fn build_withdrawal_ol_logs(intents: &[(u64, OperatorSelection)]) -> Vec<OLLog> {
    intents
        .iter()
        .map(|(amt, sel)| {
            // P2WPKH descriptor: type tag 0x00 + 20-byte hash = 21 bytes
            let hash160 = [0x14; 20];
            let descriptor = Descriptor::new_p2wpkh(&hash160);
            let dest = descriptor.to_bytes();

            let withdrawal_data = SimpleWithdrawalIntentLogData::new(*amt, dest, sel.raw())
                .expect("withdrawal intent creation should not fail");

            OLLog::from_log(BRIDGE_GATEWAY_ACCT_SERIAL, &withdrawal_data)
                .expect("withdrawal intent log encoding should not fail")
        })
        .collect()
}

// ============================================================================
// Checkpoint transaction building
// ============================================================================

impl AsmTestHarness {
    /// Build a checkpoint envelope transaction WITHOUT submitting or mining it, advancing one
    /// epoch from the checkpoint harness's current verified tip.
    ///
    /// Returns the (unsubmitted) reveal transaction and the [`CheckpointTip`] it commits to.
    /// The caller is responsible for submitting/mining the tx and calling
    /// [`CheckpointTestHarness::update_verified_tip`] once the checkpoint is accepted.
    ///
    /// Unlike `submit_checkpoint_with_withdrawal_intents`, this does not mutate the harness, so
    /// callers can build several checkpoints against a manually-advanced tip (e.g. two
    /// sequential checkpoints destined for the same block). `ol_logs` carries the checkpoint's
    /// orchestration-layer logs (e.g. withdrawal intents); pass `vec![]` for none.
    pub async fn build_checkpoint_tx(
        &self,
        checkpoint_harness: &CheckpointTestHarness,
        ol_logs: Vec<OLLog>,
    ) -> anyhow::Result<(Transaction, CheckpointTip)> {
        let verified_l1 = checkpoint_harness.verified_tip().l1_height();

        // The MMR is height-indexed (sentinel prefill for `0..=genesis`), so the highest
        // processed real L1 height is `len - 1`. Clamp so we never regress below the
        // verified tip, which yields an empty L1 range (valid: zero L1 progress allowed).
        let new_l1_height = (self.get_mmr_leaves().len() as u32)
            .saturating_sub(1)
            .max(verified_l1);

        let new_epoch = checkpoint_harness.verified_tip().epoch + 1;
        let new_ol_slot = checkpoint_harness.verified_tip().l2_commitment().slot() + 1;
        let new_ol_blkid: OLBlockId = ArbitraryGenerator::new().generate();
        let new_ol_commitment = OLBlockCommitment::new(new_ol_slot, new_ol_blkid);
        let new_tip = CheckpointTip::new(new_epoch, new_l1_height, new_ol_commitment);

        let tx = self
            .build_checkpoint_tx_for_tip(checkpoint_harness, new_tip, ol_logs)
            .await?;
        Ok((tx, new_tip))
    }

    /// Build a checkpoint envelope transaction for an explicitly chosen [`CheckpointTip`].
    ///
    /// Lets callers construct checkpoints whose tip deliberately violates the progression
    /// rules (e.g. a skipped epoch) to exercise rejection paths. The committed manifest range
    /// is taken relative to the harness's current verified tip.
    pub async fn build_checkpoint_tx_for_tip(
        &self,
        checkpoint_harness: &CheckpointTestHarness,
        new_tip: CheckpointTip,
        ol_logs: Vec<OLLog>,
    ) -> anyhow::Result<Transaction> {
        let verified_l1 = checkpoint_harness.verified_tip().l1_height();
        let manifest_hashes = self.checkpoint_manifest_leaves(verified_l1, new_tip.l1_height());

        let payload =
            checkpoint_harness.build_payload_with_tip_and_logs(new_tip, ol_logs, &manifest_hashes);

        let codec_payload = CodecSsz::new(payload);
        let payload_bytes = encode_to_vec(&codec_payload).expect("codec encoding should not fail");
        let checkpoint_tag = TagData::new(1, 1, vec![]).expect("valid checkpoint tag");
        let secp = Secp256k1::new();
        let sequencer_keypair =
            UntweakedKeypair::from_seckey_slice(&secp, checkpoint_harness.sequencer_secret_key())?;
        self.build_envelope_tx_with_keypair(checkpoint_tag, payload_bytes, &sequencer_keypair)
            .await
    }

    /// Collect the live ASM MMR manifest hashes for L1 heights `(verified_l1, new_l1_height]`.
    ///
    /// Returns an empty vec when the range is empty (`new_l1_height <= verified_l1`), matching
    /// the validator's `AsmManifestRangeHash::ZERO` for an empty L1 range.
    fn checkpoint_manifest_leaves(
        &self,
        verified_l1: u32,
        new_l1_height: u32,
    ) -> Vec<AsmManifestHash> {
        if new_l1_height <= verified_l1 {
            return Vec::new();
        }
        let mmr_leaves = self.get_mmr_leaves();
        let start = (verified_l1 + 1) as usize;
        let end = new_l1_height as usize;
        mmr_leaves[start..=end]
            .iter()
            .copied()
            .map(AsmManifestHash::from)
            .collect()
    }
}

// ============================================================================
// Test Setup
// ============================================================================

/// Creates matching checkpoint config and test harness for integration tests.
///
/// Generates signing keys and returns a [`CheckpointInitConfig`] (for the harness builder)
/// and a [`CheckpointTestHarness`] (for building checkpoint payloads).
pub fn create_test_checkpoint_setup(
    genesis_l1_height: u32,
) -> (CheckpointInitConfig, CheckpointTestHarness) {
    let genesis_ol_blkid: OLBlockId = ArbitraryGenerator::new().generate();
    let harness = CheckpointTestHarness::new_with_genesis(genesis_l1_height, genesis_ol_blkid);

    let config = CheckpointInitConfig {
        sequencer_predicate: harness.sequencer_predicate(),
        checkpoint_predicate: harness.checkpoint_predicate(),
        genesis_l1_height,
        genesis_ol_blkid,
    };

    (config, harness)
}
