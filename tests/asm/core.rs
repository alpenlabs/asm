//! Core ASM worker integration tests
//!
//! Tests the ASM worker's ability to process Bitcoin blocks and maintain state.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use bitcoin::Network;
use harness::{test_harness::AsmTestHarnessBuilder, worker_context::TestAsmWorkerContext};
use integration_tests::harness;
use strata_asm_worker::WorkerContext;
use strata_btc_types::BlockHashExt;
use strata_test_utils_btcio::{get_bitcoind_and_client, mine_blocks};

// ============================================================================
// Worker Context
// ============================================================================

/// Verifies worker context initializes with correct defaults.
#[tokio::test(flavor = "multi_thread")]
async fn test_worker_context_initialization() {
    let (_bitcoind, client) = get_bitcoind_and_client();
    let context = TestAsmWorkerContext::new(client);

    assert_eq!(context.get_network().unwrap(), Network::Regtest);
    assert!(context.get_latest_asm_state().unwrap().is_none());
}

/// Verifies blocks are fetched from regtest and cached.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_fetching_and_caching() {
    let (bitcoind, client) = get_bitcoind_and_client();
    let context = TestAsmWorkerContext::new(client);

    // Mine 5 blocks
    let block_hashes = mine_blocks(&bitcoind, context.client.as_ref(), 5, None)
        .await
        .expect("Failed to mine blocks");

    // Fetch each block through the context
    for block_hash in block_hashes.iter() {
        let block_id = block_hash.to_l1_block_id();
        context
            .get_l1_block(&block_id)
            .expect("Failed to get block");
    }

    // Verify blocks are cached
    assert_eq!(context.inner.lock().unwrap().block_cache.len(), 5);

    // Fetch again - should come from cache
    let block_id = block_hashes[0].to_l1_block_id();
    let block = context
        .get_l1_block(&block_id)
        .expect("Failed to get cached block");
    assert_eq!(block.block_hash(), block_hashes[0]);
}

// ============================================================================
// Block Processing
// ============================================================================

/// Verifies ASM worker processes a single mined block.
#[tokio::test(flavor = "multi_thread")]
async fn test_single_block_processing() {
    let harness = AsmTestHarnessBuilder::default()
        .build()
        .await
        .expect("Failed to create test harness");

    harness
        .mine_block(None)
        .await
        .expect("Failed to mine block");

    let tip_height = harness
        .get_chain_tip()
        .await
        .expect("Failed to get chain tip");
    assert_eq!(tip_height, harness.genesis_height + 1);
}

/// Verifies the worker does not produce or store a manifest for the genesis
/// block, and that the first stored manifest is for `genesis_height + 1`.
///
/// The genesis MMR slot is occupied by the prefill sentinel; appending a
/// genesis manifest would shift every subsequent leaf one position past its
/// L1 height and break alignment between the proven and external MMRs.
#[tokio::test(flavor = "multi_thread")]
async fn test_genesis_manifest_not_stored() {
    let harness = AsmTestHarnessBuilder::default()
        .build()
        .await
        .expect("Failed to create test harness");

    // Right after init: no blocks processed, no manifests stored.
    assert!(
        harness.get_stored_manifests().is_empty(),
        "no manifest should be stored before any post-genesis block is processed"
    );

    // Mine one block on top of genesis and verify exactly one manifest is
    // stored, at height `genesis_height + 1`.
    harness
        .mine_block(None)
        .await
        .expect("Failed to mine block");

    let manifests = harness.get_stored_manifests();
    assert_eq!(
        manifests.len(),
        1,
        "mining one block should produce exactly one stored manifest, got {}",
        manifests.len()
    );
    assert_eq!(
        manifests[0].height() as u64,
        harness.genesis_height + 1,
        "first stored manifest should be for height `genesis_height + 1`"
    );
}

/// Verifies ASM worker processes multiple mined blocks.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_block_processing() {
    let harness = AsmTestHarnessBuilder::default()
        .build()
        .await
        .expect("Failed to create test harness");
    let (l1, state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(l1, state.state().chain_view.pow_state.last_verified_block);
    assert_eq!(
        l1.height() as u64,
        state
            .state()
            .chain_view
            .history_accumulator
            .last_inserted_height()
    );

    let block_hashes = harness.mine_blocks(3).await.expect("Failed to mine blocks");
    assert_eq!(block_hashes.len(), 3);

    let tip_height = harness
        .get_chain_tip()
        .await
        .expect("Failed to get chain tip");
    assert_eq!(tip_height, harness.genesis_height + 3);
    assert_eq!(l1, state.state().chain_view.pow_state.last_verified_block);
    assert_eq!(
        l1.height() as u64,
        state
            .state()
            .chain_view
            .history_accumulator
            .last_inserted_height()
    );
}

// ============================================================================
// MMR Integrity
// ============================================================================
//
// The ASM maintains two MMR representations of manifest hashes:
//
// **Internal (proven) MMR** — `CompactMmr64` inside `AnchorState.chain_view.history_accumulator`.
//   - Lives inside the ASM state that gets proven in the ZKVM.
//   - Compact representation: stores only peaks, not all leaves. Keeps the proven state small.
//   - Can *verify* inclusion proofs but cannot *generate* them.
//   - Updated by the STF during `compute_asm_transition`.
//   - Height-indexed: at genesis it is prefilled with `MMR_PREFILL_LEAF` sentinels for every L1
//     height `0..=genesis_height`, so the manifest for L1 height `h` lands at MMR leaf index `h`.
//     The first appended real manifest is for `genesis_height + 1`.
//
// **External (full) MMR** — the worker-side database managed by `WorkerContext`.
//   - Lives outside the proven state, in the worker's persistent storage.
//   - Full tree: stores all leaves and intermediate nodes.
//   - Can *generate* inclusion proofs for any leaf via `generate_mmr_proof`.
//   - Populated by the ASM worker after each STF execution.
//
// **How they interact during checkpoint verification:**
//   1. A checkpoint tx on L1 references a range of L1 block heights.
//   2. `AuxDataResolver` uses the external MMR to generate inclusion proofs for the manifest hashes
//      at those heights.
//   3. These proofs are passed as auxiliary data into the STF.
//   4. Inside the STF, the checkpoint subprotocol verifies those proofs against the internal
//      compact MMR.
//
// The two MMRs must have identical leaves at identical indices. Both are
// height-indexed (sentinel-prefilled at and before genesis); if either side
// appended the genesis manifest, all subsequent indices would shift by 1 and
// every proof generated from the external MMR would fail verification against
// the internal one.

/// Verifies the external (full) MMR stays index-aligned with the internal
/// (proven compact) MMR after block processing.
///
/// Mines blocks in multiple rounds and checks alignment after each round to
/// verify the invariant holds incrementally, not just at the end.
#[tokio::test(flavor = "multi_thread")]
async fn test_proven_and_external_mmr_index_alignment() {
    let harness = AsmTestHarnessBuilder::default()
        .build()
        .await
        .expect("Failed to create test harness");

    let genesis_height = harness.genesis_height;

    // After genesis processing, both MMRs are height-indexed and prefilled
    // with `MMR_PREFILL_LEAF` sentinels for every L1 height `0..=genesis_height`.
    // The worker never produces or stores a manifest for the genesis block;
    // the first real manifest is for the block at `genesis_height + 1`.
    let prefill_count = genesis_height + 1;
    assert_eq!(
        harness.get_mmr_leaf_count() as u64,
        prefill_count,
        "external MMR should be sentinel-prefilled to `genesis_height + 1` entries"
    );

    // Mine blocks in multiple rounds of increasing size to exercise the MMR
    // across different tree shapes (powers of two, odd counts, etc.).
    // The compact MMR's internal peak structure changes at each power-of-two
    // boundary, so we want to cross several of them.
    let rounds: &[usize] = &[1, 3, 4, 8, 16];
    let mut total_blocks_mined: usize = 0;

    for (round, &count) in rounds.iter().enumerate() {
        let block_hashes = harness
            .mine_blocks(count)
            .await
            .unwrap_or_else(|e| panic!("round {round}: failed to mine {count} blocks: {e}"));
        assert_eq!(block_hashes.len(), count);
        total_blocks_mined += count;

        // -- Proven (internal) compact MMR --
        let (_commitment, latest_state) = harness
            .get_latest_asm_state()
            .unwrap_or_else(|e| panic!("round {round}: failed to get ASM state: {e}"))
            .unwrap_or_else(|| panic!("round {round}: ASM state should exist"));

        let proven_accumulator = &latest_state.state().chain_view.history_accumulator;
        let proven_tip_height = proven_accumulator.last_inserted_height();
        let proven_entries = proven_accumulator.num_entries();

        assert_eq!(
            proven_tip_height,
            genesis_height + total_blocks_mined as u64,
            "round {round}: proven MMR tip should be genesis + {total_blocks_mined}"
        );

        // -- External (full) MMR --
        let external_leaf_count = harness.get_mmr_leaf_count();

        // Core invariant: both MMRs must have the same number of leaves.
        // Both are height-indexed with `genesis_height + 1` prefill sentinels
        // plus one real leaf per mined block.
        assert_eq!(
            proven_entries as usize,
            external_leaf_count,
            "round {round}: proven and external MMR leaf counts must match \
             (both should be {} = genesis_height + 1 + {total_blocks_mined})",
            genesis_height + 1 + total_blocks_mined as u64
        );
    }

    // -- Leaf hash integrity over real (post-genesis) leaves --
    // Verify every post-genesis external MMR leaf matches its corresponding
    // manifest hash. Indices `0..=genesis_height` are prefill sentinels and
    // are skipped here.
    let external_leaves = harness.get_mmr_leaves();
    let stored_manifests = harness.get_stored_manifests();
    let prefill_count = (genesis_height + 1) as usize;

    assert_eq!(
        external_leaves.len(),
        prefill_count + total_blocks_mined,
        "final external MMR should have {prefill_count} prefill + {total_blocks_mined} real leaves"
    );

    let sentinel = strata_asm_common::MMR_SENTINEL_DUMMY_LEAF;
    for (mmr_index, leaf) in external_leaves.iter().take(prefill_count).enumerate() {
        assert_eq!(
            *leaf, sentinel,
            "pre-genesis leaf at index {mmr_index} must be the prefill sentinel"
        );
    }

    for (mmr_index, external_leaf_hash) in external_leaves.iter().enumerate().skip(prefill_count) {
        let block_height = mmr_index as u64;
        let manifest = stored_manifests
            .iter()
            .find(|m| m.height() as u64 == block_height)
            .unwrap_or_else(|| panic!("no stored manifest for height {block_height}"));

        let proven_leaf_hash: [u8; 32] = *manifest.compute_hash().as_ref();
        assert_eq!(
            *external_leaf_hash, proven_leaf_hash,
            "leaf hash mismatch at MMR index {mmr_index} (L1 height {block_height}): \
             external MMR disagrees with manifest compute_hash()"
        );
    }

    // No manifest should ever be stored for the genesis block; the worker
    // skips genesis entirely and only stores manifests for post-genesis blocks.
    assert!(
        stored_manifests
            .iter()
            .all(|m| (m.height() as u64) > genesis_height),
        "no manifest should be stored for genesis (or earlier) heights; \
         got heights {:?}",
        stored_manifests
            .iter()
            .map(|m| m.height())
            .collect::<Vec<_>>()
    );

    // The genesis MMR slot must remain the prefill sentinel.
    assert_eq!(
        external_leaves[genesis_height as usize], sentinel,
        "genesis MMR slot must hold the prefill sentinel"
    );
}
