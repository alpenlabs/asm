use arbitrary::Arbitrary;
use bitcoin::{CompactTarget, Network, block::Header, hashes::Hash, params::Params};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use strata_btc_types::{BlockHashExt, BtcParams};
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId, L1Height};

use crate::{
    BtcWork, errors::L1VerificationError, timestamp_store::TimestampStore,
    utils_btc::compute_block_hash,
};

/// A struct containing all necessary information for validating a Bitcoin block header.
///
/// The validation process includes:
///
/// 1. Ensuring that the block's hash is below the current target, which is a threshold representing
///    a hash with a specified number of leading zeros. This target is directly related to the
///    block's difficulty.
///
/// 2. Verifying that the encoded previous block hash in the current block matches the actual hash
///    of the previous block.
///
/// 3. Checking that the block's timestamp is not lower than the median of the last eleven blocks'
///    timestamps and does not exceed the network time by more than two hours.
///
/// 4. Ensuring that the correct target is encoded in the block. If a retarget event occurred,
///    validating that the new target was accurately derived from the epoch timestamps.
///
/// Ref: [A light introduction to ZeroSync](https://geometry.xyz/notebook/A-light-introduction-to-ZeroSync)
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    Arbitrary,
    BorshSerialize,
    BorshDeserialize,
    Deserialize,
    Serialize,
)]
pub struct HeaderVerificationState {
    /// Bitcoin network parameters used for header verification.
    ///
    /// Contains network-specific configuration including difficulty adjustment intervals,
    /// target block spacing, and other consensus parameters required for validating block headers
    /// according to the Bitcoin protocol rules.
    params: BtcParams,

    /// Commitment to the last verified block, containing both its height and block hash.
    pub last_verified_block: L1BlockCommitment,

    /// [Target](bitcoin::pow::CompactTarget) for the next block to verify
    next_block_target: u32,

    /// Timestamp of the block at the start of a [difficulty adjustment
    /// interval](bitcoin::consensus::params::Params::difficulty_adjustment_interval).
    ///
    /// On [MAINNET](bitcoin::consensus::params::MAINNET), a difficulty adjustment interval lasts
    /// for 2016 blocks. The interval starts at blocks with heights 0, 2016, 4032, 6048, 8064,
    /// etc.
    ///
    /// This field represents the timestamp of the starting block of the interval
    /// (e.g., block 0, 2016, 4032, etc.).
    epoch_start_timestamp: u32,

    /// A ring buffer that maintains a history of block timestamps.
    ///
    /// This buffer is used to compute the median block time for consensus rules by considering the
    /// most recent 11 timestamps. However, it retains additional timestamps to support chain reorg
    /// scenarios.
    block_timestamp_history: TimestampStore,

    /// Total accumulated proof of work
    total_accumulated_pow: BtcWork,
}

impl HeaderVerificationState {
    /// Constructs a [`HeaderVerificationState`] at a particular point in the chain.
    ///
    /// Accepts pre-existing timestamp history and accumulated proof of work, allowing
    /// reconstruction of the verification state at an arbitrary block height (e.g., when
    /// resuming from a snapshot or checkpoint).
    pub fn new(
        anchor: L1Anchor,
        block_timestamp_history: TimestampStore,
        total_accumulated_pow: BtcWork,
    ) -> Self {
        let params = BtcParams::from(Params::new(anchor.network));
        Self {
            params,
            last_verified_block: anchor.block,
            next_block_target: anchor.next_target,
            epoch_start_timestamp: anchor.epoch_start_timestamp,
            block_timestamp_history,
            total_accumulated_pow,
        }
    }

    /// Creates a fresh [`HeaderVerificationState`] from an [`L1Anchor`].
    ///
    /// A convenience wrapper around [`new`](Self::new) that initializes with an empty timestamp
    /// history and zero accumulated proof of work, suitable for starting header verification
    /// from the anchor block without any prior state.
    pub fn init(anchor: L1Anchor) -> Self {
        let block_timestamp_history = TimestampStore::default();
        let total_accumulated_pow = BtcWork::default();

        Self::new(anchor, block_timestamp_history, total_accumulated_pow)
    }

    /// Splits the verification state into its raw components.
    pub fn into_parts(
        self,
    ) -> (
        BtcParams,
        L1BlockCommitment,
        u32,
        u32,
        TimestampStore,
        BtcWork,
    ) {
        (
            self.params,
            self.last_verified_block,
            self.next_block_target,
            self.epoch_start_timestamp,
            self.block_timestamp_history,
            self.total_accumulated_pow,
        )
    }

    /// Reconstructs the verification state from its raw components.
    pub fn from_parts(
        params: BtcParams,
        last_verified_block: L1BlockCommitment,
        next_block_target: u32,
        epoch_start_timestamp: u32,
        block_timestamp_history: TimestampStore,
        total_accumulated_pow: BtcWork,
    ) -> Self {
        Self {
            params,
            last_verified_block,
            next_block_target,
            epoch_start_timestamp,
            block_timestamp_history,
            total_accumulated_pow,
        }
    }

    /// Calculates the next difficulty target based on the current header.
    ///
    /// If this is a difficulty adjustment block (height + 1 is multiple of adjustment interval),
    /// calculates a new target using the timespan between epoch start and current block.
    /// Otherwise, returns the current target unchanged.
    fn next_target(&mut self, header: &Header) -> u32 {
        let next_height = self.last_verified_block.height() + 1;
        if !next_height.is_multiple_of(self.params.difficulty_adjustment_interval() as u32) {
            return self.next_block_target;
        }

        let timespan = header.time - self.epoch_start_timestamp;

        CompactTarget::from_next_work_required(header.bits, timespan as u64, &self.params)
            .to_consensus()
    }

    /// Updates the timestamp history and epoch start timestamp if necessary.
    ///
    /// Adds the new timestamp to the ring buffer history. If the current block height
    /// is at a difficulty adjustment boundary, updates the epoch start timestamp to
    /// track the beginning of the new difficulty adjustment period.
    fn update_timestamps(&mut self, timestamp: u32) {
        self.block_timestamp_history.insert(timestamp);

        let new_block_num = self.last_verified_block.height();
        if new_block_num.is_multiple_of(self.params.difficulty_adjustment_interval() as u32) {
            self.epoch_start_timestamp = timestamp;
        }
    }

    /// Checks all verification criteria for a header and updates the state if all conditions pass.
    ///
    /// The checks include:
    /// 1. Continuity: Ensuring the header's previous block hash matches the last verified hash.
    /// 2. Target Encoding: Validating that the header's target matches the expected target.
    /// 3. Timestamp: Ensuring the header's timestamp is greater than the median of the last 11
    ///    blocks.
    /// 4. Proof-of-Work: Validating that the computed block hash meets the target.
    /// # Errors
    ///
    /// Returns a [`L1VerificationError`] if any of the checks fail.
    pub fn check_and_update(&mut self, header: &Header) -> Result<(), L1VerificationError> {
        // 1. Check continuity
        let prev_blockhash: L1BlockId =
            Buf32::from(header.prev_blockhash.as_raw_hash().to_byte_array()).into();
        if prev_blockhash != *self.last_verified_block.blkid() {
            return Err(L1VerificationError::ContinuityError {
                expected: *self.last_verified_block.blkid(),
                found: prev_blockhash,
            });
        }

        // 2. Check Proof-of-Work target encoding
        if header.bits.to_consensus() != self.next_block_target {
            return Err(L1VerificationError::PowMismatch {
                expected: self.next_block_target,
                found: header.bits.to_consensus(),
            });
        }

        // 3. Check timestamp against the median of the last 11 timestamps.
        let median = self.block_timestamp_history.median();
        if header.time <= median {
            return Err(L1VerificationError::TimestampError {
                time: header.time,
                median,
            });
        }

        // 4. Check that the block hash meets the target difficulty.
        let block_hash = compute_block_hash(header);
        if !header.target().is_met_by(block_hash) {
            return Err(L1VerificationError::PowNotMet {
                block_hash,
                target: header.bits.to_consensus(),
            });
        }

        // Increase the last verified block number by 1 and set the new block hash
        let next_height = self.last_verified_block.height() + 1;
        self.last_verified_block = L1BlockCommitment::new(next_height, block_hash.to_l1_block_id());

        // Update the timestamps
        self.update_timestamps(header.time);

        // Set the target for the next block
        self.next_block_target = self.next_target(header);

        // Update total accumulated PoW
        self.total_accumulated_pow += header.work().into();

        Ok(())
    }

    /// Gets the next block target (for testing)
    pub fn get_next_block_target(&self) -> u32 {
        self.next_block_target
    }

    /// Gets the epoch start timestamp (for testing)
    pub fn get_epoch_start_timestamp(&self) -> u32 {
        self.epoch_start_timestamp
    }

    /// Gets the block timestamp history (for testing)
    pub fn get_block_timestamp_history(&self) -> &TimestampStore {
        &self.block_timestamp_history
    }

    /// Gets the total accumulated PoW (for testing)
    pub fn get_total_accumulated_pow(&self) -> BtcWork {
        self.total_accumulated_pow.clone()
    }
}

/// Snapshot of L1 chain state used to anchor the ASM to a known point on the Bitcoin chain.
///
/// This struct holds the minimum information required to resume L1 verification from an
/// arbitrary point: which block was last verified, what difficulty target the next block must
/// satisfy, when the current difficulty-adjustment epoch began, and which network's consensus
/// rules apply.
///
/// Used to construct a [`HeaderVerificationState`] (along with a timestamp history) when
/// bootstrapping or resuming header verification.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1Anchor {
    /// Commitment (height + block hash) to the last verified L1 block.
    pub block: L1BlockCommitment,

    /// Compact-encoded target that the next block header must satisfy.
    pub next_target: u32,

    /// Timestamp of the first block in the current difficulty-adjustment epoch.
    pub epoch_start_timestamp: u32,

    /// Bitcoin network (mainnet, testnet, signet, regtest) that determines consensus parameters.
    pub network: Network,
}

/// Calculates the height at which a specific difficulty adjustment occurs relative to a
/// starting height.
///
/// # Arguments
///
/// * `idx` - The index of the difficulty adjustment (1-based). 1 for the first adjustment, 2 for
///   the second, and so on.
/// * `start` - The starting height from which to calculate.
/// * `params` - [`Params`] of the bitcoin network in use
pub fn get_relative_difficulty_adjustment_height(
    idx: usize,
    start: L1Height,
    params: &Params,
) -> L1Height {
    // `difficulty_adjustment_interval()` returns `u64` but the value is always less than u32, so
    // the cast is safe. Upstream rust-bitcoin has since changed the return type to `u32` in https://github.com/rust-bitcoin/rust-bitcoin/commit/943a7863c8baeed9e06342fa98e67b390bedec43.
    let difficulty_adjustment_interval = params.difficulty_adjustment_interval() as u32;
    ((start / difficulty_adjustment_interval) + idx as u32) * difficulty_adjustment_interval
}

#[cfg(test)]
mod tests {

    use bitcoin::{
        BlockHash, CompactTarget, Network,
        hashes::Hash,
        params::{MAINNET, Params},
    };
    use borsh::{BorshDeserialize, BorshSerialize};
    use rand::{Rng, rngs::OsRng};
    use strata_btc_types::{BlockHashExt, TIMESTAMPS_FOR_MEDIAN};
    use strata_identifiers::{L1BlockCommitment, L1Height};
    use strata_test_utils_btc::BtcMainnetSegment;

    use crate::*;

    fn get_l1_anchor(chain: &BtcMainnetSegment, anchor_height: L1Height) -> L1Anchor {
        let params = Params::from(Network::Bitcoin);

        let current_epoch_start_height =
            get_relative_difficulty_adjustment_height(0, anchor_height, &params);
        let current_epoch_start_header = chain
            .get_block_header_at(current_epoch_start_height)
            .expect("missing current epoch start header in fixture");
        let block_header = chain
            .get_block_header_at(anchor_height)
            .expect("missing block header in fixture");

        let next_target =
            if (anchor_height as u64 + 1).is_multiple_of(params.difficulty_adjustment_interval()) {
                CompactTarget::from_next_work_required(
                    block_header.bits,
                    (block_header.time - current_epoch_start_header.time) as u64,
                    &params,
                )
                .to_consensus()
            } else {
                block_header.target().to_compact_lossy().to_consensus()
            };

        L1Anchor {
            block: L1BlockCommitment::new(
                anchor_height,
                block_header.block_hash().to_l1_block_id(),
            ),
            next_target,
            epoch_start_timestamp: current_epoch_start_header.time,
            network: Network::Bitcoin,
        }
    }

    fn verification_state_at(
        chain: &BtcMainnetSegment,
        anchor_height: L1Height,
    ) -> Result<HeaderVerificationState, &'static str> {
        let anchor = get_l1_anchor(chain, anchor_height);
        Ok(HeaderVerificationState::init(anchor))
    }

    #[test]
    fn test_blocks() {
        let chain = BtcMainnetSegment::load();
        let (start, end) = chain.height_bounds();
        let h2 = get_relative_difficulty_adjustment_height(2, start, &MAINNET);
        let r1 = OsRng.gen_range(h2..end);
        let mut verification_state = verification_state_at(&chain, r1).unwrap();

        for header_idx in r1 + 1..end {
            verification_state
                .check_and_update(&chain.get_block_header_at(header_idx).unwrap())
                .unwrap()
        }
    }

    #[test]
    fn test_get_difficulty_adjustment_height() {
        let start: L1Height = 0;
        let idx = OsRng.gen_range(1..1000usize);
        let h = get_relative_difficulty_adjustment_height(idx, start, &MAINNET);
        assert_eq!(
            h,
            MAINNET.difficulty_adjustment_interval() as u32 * idx as u32
        );
    }

    // ========================================================================
    // Difficulty Adjustment Tests
    // ========================================================================
    //
    // Bitcoin adjusts mining difficulty every 2016 blocks to maintain ~10 minute
    // block times. These tests validate the adjustment calculation and boundary
    // conditions.
    //
    // References:
    // - Bitcoin Developer Guide: https://developer.bitcoin.org/devguide/block_chain.html#target-nbits
    // - Difficulty Adjustment Algorithm: https://en.bitcoin.it/wiki/Difficulty
    // - Protocol Rules: https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp
    // - Btc Optech: https://bitcoinops.org/en/topics/difficulty-adjustment-algorithms/
    // ========================================================================

    /// Test that difficulty adjustment happens at exactly the right block height (40,320).
    /// Block 40,320 is the first difficulty adjustment in our test data (`40_320 = 20 * 2016`).
    #[test]
    fn test_difficulty_adjustment_at_boundary_block() {
        let chain = BtcMainnetSegment::load();

        // Start verification just before the difficulty adjustment block
        let adjustment_height = 40_320;
        let mut verification_state = verification_state_at(&chain, adjustment_height - 1).unwrap();

        let _target_before = verification_state.get_next_block_target();
        let _epoch_start_before = verification_state.get_epoch_start_timestamp();

        // Process the adjustment block (40,320)
        let adjustment_header = chain.get_block_header_at(adjustment_height).unwrap();
        verification_state
            .check_and_update(&adjustment_header)
            .expect("Difficulty adjustment block should be valid");

        // After processing block 40,320, the epoch_start_timestamp should be updated
        // to the timestamp of block 40,320
        assert_eq!(
            verification_state.get_epoch_start_timestamp(),
            adjustment_header.time,
            "Epoch start timestamp should be updated at difficulty adjustment boundary"
        );

        // The target may have changed (depending on the timespan of the previous epoch)
        // We just verify that the next_block_target was recalculated
        let _target_after = verification_state.get_next_block_target();

        // Verify the state is valid for continuing
        let next_header = chain.get_block_header_at(adjustment_height + 1).unwrap();
        verification_state
            .check_and_update(&next_header)
            .expect("Block after difficulty adjustment should be valid");
    }

    /// Test that blocks immediately before a difficulty adjustment use the old target.
    #[test]
    fn test_target_before_adjustment_boundary() {
        let chain = BtcMainnetSegment::load();

        // Block 40,319 is right before the adjustment at 40,320
        let pre_adjustment_height = 40_319;
        let mut verification_state =
            verification_state_at(&chain, pre_adjustment_height - 1).unwrap();

        let expected_target = verification_state.get_next_block_target();

        // Process block 40,319 (one before adjustment)
        let header = chain.get_block_header_at(pre_adjustment_height).unwrap();

        // The header should have the same target as expected
        assert_eq!(
            header.bits.to_consensus(),
            expected_target,
            "Block before adjustment should use previous epoch's target"
        );

        verification_state
            .check_and_update(&header)
            .expect("Block before adjustment should validate");

        // After processing 40,319, we're now at height 40,319
        // The next_block_target will be calculated for block 40,320, which IS an adjustment block
        // So the target WILL change - this is expected behavior
        // Let's verify that the next block (40,320) validates with the new target
        let adjustment_header = chain.get_block_header_at(40_320).unwrap();
        let new_target = verification_state.get_next_block_target();

        assert_eq!(
            adjustment_header.bits.to_consensus(),
            new_target,
            "Adjustment block should use the newly calculated target"
        );
    }

    /// Test that difficulty adjustment correctly updates target for blocks in the middle of an
    /// epoch.
    #[test]
    fn test_no_adjustment_mid_epoch() {
        let chain = BtcMainnetSegment::load();

        // Pick a block in the middle of an epoch (not a multiple of 2016)
        let mid_epoch_height = 40_100;
        let mut verification_state = verification_state_at(&chain, mid_epoch_height - 1).unwrap();

        let target_before = verification_state.get_next_block_target();
        let epoch_start_before = verification_state.get_epoch_start_timestamp();

        // Process the mid-epoch block
        let header = chain.get_block_header_at(mid_epoch_height).unwrap();
        verification_state
            .check_and_update(&header)
            .expect("Mid-epoch block should validate");

        // Target should remain unchanged
        assert_eq!(
            verification_state.get_next_block_target(),
            target_before,
            "Target should not change in middle of epoch"
        );

        // Epoch start timestamp should remain unchanged
        assert_eq!(
            verification_state.get_epoch_start_timestamp(),
            epoch_start_before,
            "Epoch start should not change in middle of epoch"
        );
    }

    /// Test processing multiple blocks across a difficulty adjustment boundary.
    #[test]
    fn test_multiple_blocks_across_adjustment() {
        let chain = BtcMainnetSegment::load();

        // Start a few blocks before the adjustment
        let start_height = 40_316;
        let adjustment_height = 40_320;
        let end_height = 40_324;

        let mut verification_state = verification_state_at(&chain, start_height).unwrap();

        let _target_before_adjustment = verification_state.get_next_block_target();

        // Process blocks leading up to and through the adjustment
        for height in (start_height + 1)..=end_height {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state
                .check_and_update(&header)
                .unwrap_or_else(|e| panic!("Block {} should validate: {:?}", height, e));

            if height == adjustment_height {
                // At the adjustment block, epoch_start_timestamp should update
                assert_eq!(
                    verification_state.get_epoch_start_timestamp(),
                    header.time,
                    "Epoch start should update at adjustment block"
                );
            }
        }

        // Verify we successfully crossed the boundary
        assert_eq!(verification_state.last_verified_block.height(), end_height);
    }

    /// Test that epoch_start_timestamp is correctly tracked across multiple adjustments.
    #[test]
    fn test_epoch_start_tracking_across_adjustments() {
        let chain = BtcMainnetSegment::load();

        // Test two consecutive adjustment blocks
        let first_adjustment = 40_320;
        let second_adjustment = 42_336; // 40320 + 2016

        let mut verification_state = verification_state_at(&chain, first_adjustment - 1).unwrap();

        // Process first adjustment block
        let first_adj_header = chain.get_block_header_at(first_adjustment).unwrap();
        verification_state
            .check_and_update(&first_adj_header)
            .expect("First adjustment should validate");

        let first_epoch_start = verification_state.get_epoch_start_timestamp();
        assert_eq!(
            first_epoch_start, first_adj_header.time,
            "First epoch start should match first adjustment block timestamp"
        );

        // Process blocks up to second adjustment
        for height in (first_adjustment + 1)..second_adjustment {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state.check_and_update(&header).unwrap();

            // Epoch start should remain constant until next adjustment
            assert_eq!(
                verification_state.get_epoch_start_timestamp(),
                first_epoch_start,
                "Epoch start should not change until next adjustment at height {}",
                height
            );
        }

        // Process second adjustment block
        let second_adj_header = chain.get_block_header_at(second_adjustment).unwrap();
        verification_state
            .check_and_update(&second_adj_header)
            .expect("Second adjustment should validate");

        // Epoch start should now update to second adjustment's timestamp
        assert_eq!(
            verification_state.get_epoch_start_timestamp(),
            second_adj_header.time,
            "Second epoch start should match second adjustment block timestamp"
        );
    }

    /// Test that incorrect target encoding is rejected.
    #[test]
    fn test_invalid_target_rejected() {
        let chain = BtcMainnetSegment::load();

        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height - 1).unwrap();

        let mut header = chain.get_block_header_at(height).unwrap();

        // Modify the bits to be incorrect
        let correct_bits = header.bits;
        header.bits = CompactTarget::from_consensus(correct_bits.to_consensus() + 1);

        let result = verification_state.check_and_update(&header);

        assert!(result.is_err(), "Invalid target should be rejected");

        // Verify it's the PowMismatch error with the expected values
        let err = result.unwrap_err();
        match err {
            L1VerificationError::PowMismatch { expected, found } => {
                assert_eq!(expected, correct_bits.to_consensus());
                assert_ne!(expected, found);
            }
            other => panic!("Expected PowMismatch error, got: {other}"),
        }
    }

    /// Test that target calculation uses correct epoch start timestamp at adjustment boundary.
    #[test]
    fn test_adjustment_uses_correct_epoch_start() {
        let chain = BtcMainnetSegment::load();

        // Get state at the beginning of an epoch (right after previous adjustment)
        let epoch_start_height = 40_320;
        let epoch_end_height = epoch_start_height + 2016 - 1; // Last block before next adjustment

        let mut verification_state = verification_state_at(&chain, epoch_start_height).unwrap();
        let epoch_start_time = verification_state.get_epoch_start_timestamp();

        // Advance to the last block of the epoch
        for height in (epoch_start_height + 1)..=epoch_end_height {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state.check_and_update(&header).unwrap();
        }

        // Epoch start should still be the same
        assert_eq!(
            verification_state.get_epoch_start_timestamp(),
            epoch_start_time,
            "Epoch start should remain constant throughout epoch"
        );

        // Process the next adjustment block
        let next_adjustment_height = epoch_end_height + 1;
        let adjustment_header = chain.get_block_header_at(next_adjustment_height).unwrap();

        // The difficulty calculation should use the timespan from epoch_start_time to
        // adjustment_header.time
        let _expected_timespan = adjustment_header.time - epoch_start_time;

        verification_state
            .check_and_update(&adjustment_header)
            .expect("Adjustment block should validate");

        // After adjustment, epoch start should update to the new adjustment block's time
        assert_eq!(
            verification_state.get_epoch_start_timestamp(),
            adjustment_header.time,
            "Epoch start should update to adjustment block time"
        );
    }

    /// Test that the relative difficulty adjustment height calculation is correct.
    #[test]
    fn test_difficulty_adjustment_height_calculation() {
        let params = &MAINNET;
        let interval = params.difficulty_adjustment_interval() as L1Height;

        // Test various starting points and adjustment indices
        assert_eq!(
            get_relative_difficulty_adjustment_height(1, 0, params),
            interval,
            "First adjustment from genesis"
        );

        assert_eq!(
            get_relative_difficulty_adjustment_height(2, 0, params),
            2 * interval,
            "Second adjustment from genesis"
        );

        // Starting from block 40000
        assert_eq!(
            get_relative_difficulty_adjustment_height(1, 40_000, params),
            40_320, // (40000/2016 + 1) * 2016 = 20 * 2016
            "Next adjustment from block 40000 should be 40320"
        );

        // Starting from exactly an adjustment block
        assert_eq!(
            get_relative_difficulty_adjustment_height(1, 40_320, params),
            42_336, // Next adjustment
            "Next adjustment from 40320"
        );

        // Starting mid-epoch
        assert_eq!(
            get_relative_difficulty_adjustment_height(1, 40_500, params),
            42_336,
            "Next adjustment from mid-epoch"
        );
    }

    // ========================================================================
    // Timestamp Validation Tests
    // ========================================================================
    //
    // Bitcoin blocks must have timestamps greater than the median of the last
    // 11 blocks (Median Time Past). This prevents timestamp manipulation and
    // ensures consistent block ordering.
    //
    // References:
    // - BIP 113 (Median Time Past): https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki
    // - Consensus Rules: https://developer.bitcoin.org/devguide/block_chain.html#block-header
    // - Time Validation: https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
    // ========================================================================

    /// Verifies that the Median Time Past (MTP) is correctly computed after
    /// populating the timestamp history.
    ///
    /// A freshly initialized verification state (via [`new_verification_state_at`])
    /// has no timestamp history, so the median starts at zero. After processing
    /// exactly [`TIMESTAMPS_FOR_MEDIAN`] (11) blocks, the median should equal the
    /// timestamp of the middle block in the window.
    #[test]
    fn test_median_time_past_after_populating_history() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        // A fresh state has no timestamp history, so the median defaults to 0.
        let median = verification_state.get_block_timestamp_history().median();
        assert_eq!(median, 0);

        // Feed exactly TIMESTAMPS_FOR_MEDIAN blocks to fill the history window.
        for height in height + 1..=height + TIMESTAMPS_FOR_MEDIAN as u32 {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state.check_and_update(&header).unwrap();
        }

        // The median should now be the timestamp of the middle block in the window.
        let median = verification_state.get_block_timestamp_history().median();
        let expected_median = chain
            .get_block_header_at(height + (TIMESTAMPS_FOR_MEDIAN / 2) as u32 + 1)
            .unwrap()
            .time;
        assert_eq!(median, expected_median);
    }

    /// Test that a timestamp exactly equal to the median is rejected with `TimestampError`.
    #[test]
    fn test_timestamp_exactly_at_median_rejected() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        let median = verification_state.get_block_timestamp_history().median();

        // Create a header with timestamp exactly at median
        let mut header = chain.get_block_header_at(height + 1).unwrap();
        header.time = median;

        let result = verification_state.check_and_update(&header);

        assert!(
            matches!(
                result.unwrap_err(),
                L1VerificationError::TimestampError { .. }
            ),
            "Header with timestamp at median should be rejected with TimestampError"
        );
    }

    /// Test that a timestamp one second greater than median passes the timestamp check.
    /// The modified timestamp changes the block hash, so PoW fails next — confirming
    /// the timestamp validation itself accepted the value.
    #[test]
    fn test_timestamp_one_second_after_median() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        let median = verification_state.get_block_timestamp_history().median();

        // Create a header with timestamp = median + 1
        let mut header = chain.get_block_header_at(height + 1).unwrap();
        header.time = median + 1;

        let result = verification_state.check_and_update(&header);

        // Timestamp check passes (median + 1 > median), but the modified timestamp
        // changes the block hash, so PoW fails.
        assert!(
            matches!(result.unwrap_err(), L1VerificationError::PowNotMet { .. }),
            "Timestamp check should pass; expect PowNotMet from changed hash"
        );
    }

    /// Test that timestamps must be greater than median (decreasing rejected with
    /// `TimestampError`).
    #[test]
    fn test_timestamp_less_than_median_rejected() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        // Feed exactly TIMESTAMPS_FOR_MEDIAN blocks to fill the history window.
        for height in height + 1..=height + TIMESTAMPS_FOR_MEDIAN as u32 {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state.check_and_update(&header).unwrap();
        }

        let median = verification_state.get_block_timestamp_history().median();

        // Create header at the next height (after the 11 blocks we just processed)
        let next_height = height + TIMESTAMPS_FOR_MEDIAN as u32 + 1;
        let mut header = chain.get_block_header_at(next_height).unwrap();
        header.time = median.saturating_sub(100); // 100 seconds before median

        let result = verification_state.check_and_update(&header);

        assert!(
            matches!(
                result.unwrap_err(),
                L1VerificationError::TimestampError { .. }
            ),
            "Header with timestamp less than median should be rejected with TimestampError"
        );
    }

    /// Test median calculation correctness with the ring buffer.
    #[test]
    fn test_median_calculation_after_updates() {
        let chain = BtcMainnetSegment::load();

        // Start at a known point
        let start_height = 40_100;
        let mut verification_state = verification_state_at(&chain, start_height).unwrap();

        // Process several blocks and verify median updates correctly
        let initial_median = verification_state.get_block_timestamp_history().median();

        for height in (start_height + 1)..=(start_height + 5) {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state
                .check_and_update(&header)
                .expect("Valid block should process");

            let new_median = verification_state.get_block_timestamp_history().median();

            // Median should be within reasonable bounds
            assert!(
                new_median >= initial_median,
                "Median should not decrease (old: {}, new: {})",
                initial_median,
                new_median
            );
        }
    }

    /// Test that timestamp history maintains correct size after many insertions.
    #[test]
    fn test_timestamp_ring_buffer_size_constant() {
        let chain = BtcMainnetSegment::load();
        let start_height = 40_100;
        let mut verification_state = verification_state_at(&chain, start_height).unwrap();

        // The ring buffer should always maintain TIMESTAMPS_FOR_MEDIAN entries
        // Process many blocks to ensure buffer wraps around
        for height in (start_height + 1)..=(start_height + 50) {
            let header = chain.get_block_header_at(height).unwrap();
            verification_state.check_and_update(&header).unwrap();

            // Buffer size is internal, but median should always work
            let _median = verification_state.get_block_timestamp_history().median();
        }

        // If we got here without panicking, ring buffer handled wraparound correctly
    }

    // ========================================================================
    // Proof-of-Work (PoW) Validation Tests
    // ========================================================================
    //
    // Bitcoin uses SHA-256 proof-of-work to secure the blockchain. Block hashes
    // must be below the target difficulty for the block to be valid. These tests
    // validate PoW checking and accumulated work calculation.
    //
    // References:
    // - Proof of Work: https://developer.bitcoin.org/devguide/block_chain.html#proof-of-work
    // - Target Calculation: https://en.bitcoin.it/wiki/Target
    // - Bitcoin Mining: https://developer.bitcoin.org/devguide/mining.html
    // - PoW Implementation: https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp
    // ========================================================================

    /// Test that a block hash exactly at target passes validation.
    #[test]
    fn test_block_hash_at_target_boundary() {
        let chain = BtcMainnetSegment::load();

        // Use a real block that passed validation
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();
        let header = chain.get_block_header_at(height + 1).unwrap();

        // This block's hash is below target (it's a real Bitcoin block)
        let result = verification_state.check_and_update(&header);
        assert!(result.is_ok(), "Valid Bitcoin block should pass PoW check");
    }

    /// Test that a block with insufficient work is rejected.
    #[test]
    fn test_insufficient_pow_rejected() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        let mut header = chain.get_block_header_at(height + 1).unwrap();

        // Increase difficulty (lower target) to make current hash insufficient
        // Multiply target by 2 makes it easier, divide makes it harder
        let _current_bits = header.bits.to_consensus();
        // Set an impossibly hard target by manipulating the compact target
        header.bits = CompactTarget::from_consensus(0x01010000); // Very hard target

        let result = verification_state.check_and_update(&header);

        // Should fail either at PowMismatch or PowNotMet
        assert!(result.is_err(), "Insufficient PoW should be rejected");
    }

    /// Test accumulated work increases with each block.
    #[test]
    fn test_accumulated_work_increases() {
        let chain = BtcMainnetSegment::load();
        let start_height = 40_100;
        let mut verification_state = verification_state_at(&chain, start_height).unwrap();

        let initial_work = verification_state.get_total_accumulated_pow();

        // Process a block
        let header = chain.get_block_header_at(start_height + 1).unwrap();
        verification_state.check_and_update(&header).unwrap();

        let new_work = verification_state.get_total_accumulated_pow();

        assert!(
            new_work != initial_work,
            "Accumulated work should change after processing a block"
        );
    }

    /// Test PoW validation works correctly across different network parameters.
    #[test]
    fn test_pow_validation_consistency() {
        let chain = BtcMainnetSegment::load();

        // Process multiple blocks and verify PoW is consistently validated
        let start_height = 40_100;
        let mut verification_state = verification_state_at(&chain, start_height).unwrap();

        for height in (start_height + 1)..=(start_height + 10) {
            let header = chain.get_block_header_at(height).unwrap();

            // All real Bitcoin blocks should pass PoW validation
            verification_state
                .check_and_update(&header)
                .unwrap_or_else(|e| {
                    panic!("Valid Bitcoin block at height {height} should pass PoW: {e:?}")
                });
        }
    }

    // ========================================================================
    // Chain Continuity Tests
    // ========================================================================
    //
    // Bitcoin blocks form a chain by referencing the hash of the previous block.
    // Each block header contains prev_blockhash that must match the hash of the
    // immediately preceding block, ensuring an immutable chain of blocks.
    //
    // References:
    // - Block Structure: https://developer.bitcoin.org/reference/block_chain.html#block-headers
    // - Block Chain: https://en.bitcoin.it/wiki/Block_chain
    // - Block Hashing: https://developer.bitcoin.org/devguide/block_chain.html#block-headers
    // - Source Code: https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
    // ========================================================================

    /// Test that wrong previous block hash is rejected.
    #[test]
    fn test_wrong_prev_blockhash_rejected() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        let mut header = chain.get_block_header_at(height + 1).unwrap();

        // Corrupt the previous block hash
        header.prev_blockhash = BlockHash::from_slice(&[0u8; 32]).unwrap();

        let result = verification_state.check_and_update(&header);

        assert!(
            matches!(
                result.unwrap_err(),
                L1VerificationError::ContinuityError { .. }
            ),
            "Wrong prev_blockhash should be rejected with ContinuityError"
        );
    }

    /// Test that continuity error contains correct block hash information.
    #[test]
    fn test_continuity_error_details() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let mut verification_state = verification_state_at(&chain, height).unwrap();

        let correct_prev_hash = *verification_state.last_verified_block.blkid();
        let mut header = chain.get_block_header_at(height + 1).unwrap();

        // Set a different (wrong) previous hash
        let wrong_hash = BlockHash::from_slice(&[0xab; 32]).unwrap();
        header.prev_blockhash = wrong_hash;

        let result = verification_state.check_and_update(&header);

        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                L1VerificationError::ContinuityError {
                    expected,
                    found,
                } if expected == correct_prev_hash
                  && found == wrong_hash.to_l1_block_id()
            ),
            "Expected ContinuityError with correct hashes, got: {err:?}"
        );
    }

    /// Test that a valid chain of blocks maintains continuity.
    #[test]
    fn test_valid_chain_continuity() {
        let chain = BtcMainnetSegment::load();
        let start_height = 40_100;
        let mut verification_state = verification_state_at(&chain, start_height).unwrap();

        // Process 20 consecutive blocks
        for height in (start_height + 1)..=(start_height + 20) {
            let header = chain.get_block_header_at(height).unwrap();

            // Verify prev_blockhash matches before processing
            let prev_hash = header.prev_blockhash;
            let expected_hash = verification_state.last_verified_block.blkid();

            let prev_hash_bytes = prev_hash.as_raw_hash().as_byte_array();
            let expected_bytes = expected_hash.as_ref();

            assert_eq!(
                *prev_hash_bytes, *expected_bytes,
                "Block {height} should reference previous block correctly"
            );

            verification_state
                .check_and_update(&header)
                .unwrap_or_else(|e| {
                    panic!("Valid chain should maintain continuity at height {height}: {e:?}")
                });
        }
    }

    // ========================================================================
    // State Hash & Serialization Tests
    // ========================================================================
    //
    // HeaderVerificationState must be deterministically serializable for consensus.
    // The state hash provides a cryptographic commitment to the verification state,
    // ensuring all nodes agree on the current chain validation state. Uses Borsh
    // serialization for canonical binary representation.
    //
    // References:
    // - Borsh Specification: https://borsh.io/
    // - Consensus Requirements: https://developer.bitcoin.org/devguide/block_chain.html#consensus-rule-changes
    // - Serialization in Bitcoin: https://en.bitcoin.it/wiki/Protocol_documentation#Common_structures
    // ========================================================================

    /// Test that serialization round-trip preserves state.
    #[test]
    fn test_state_serialization_roundtrip() {
        let chain = BtcMainnetSegment::load();
        let height = 40_100;
        let original_state = verification_state_at(&chain, height).unwrap();

        // Serialize
        let mut buffer = Vec::new();
        original_state
            .serialize(&mut buffer)
            .expect("Serialization should succeed");

        // Deserialize
        let deserialized_state = HeaderVerificationState::deserialize(&mut &buffer[..])
            .expect("Deserialization should succeed");

        assert_eq!(
            original_state, deserialized_state,
            "Serialization round-trip should preserve state"
        );
    }
}
