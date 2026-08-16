//! Core ASM worker integration tests
//!
//! Tests the ASM worker's ability to process Bitcoin blocks and maintain state.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use bitcoin::Network;
use harness::{
    bridge::{extract_bridge_state, BridgeExt},
    test_harness::{AsmTestHarnessBuilder, Setup},
};
use integration_tests::harness;
use strata_asm_manifest_types::AsmManifestHash;
use strata_asm_worker::{test_utils::TestAsmWorkerContext, AnchorStateStore, L1DataProvider};
use strata_btc_types::BlockHashExt;
use strata_identifiers::L1_HEIGHT_MMR_PREFILL_LEAF;
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
    assert!(context.get_latest_anchor_state().unwrap().is_none());
}

/// Verifies blocks are fetched from regtest by hash.
#[tokio::test(flavor = "multi_thread")]
async fn test_block_fetching() {
    let (bitcoind, client) = get_bitcoind_and_client();
    let context = TestAsmWorkerContext::new(client);

    // Mine 5 blocks
    let block_hashes = mine_blocks(&bitcoind, context.client.as_ref(), 5, None)
        .await
        .expect("Failed to mine blocks");

    // Fetch each block through the context and confirm it round-trips by hash.
    for block_hash in block_hashes.iter() {
        let block_id = block_hash.to_l1_block_id();
        let block = context
            .get_l1_block(&block_id)
            .expect("Failed to get block");
        assert_eq!(block.block_hash(), *block_hash);
    }
}

// ============================================================================
// Block Processing
// ============================================================================

/// Verifies ASM worker processes a single mined block.
#[tokio::test(flavor = "multi_thread")]
async fn test_single_block_processing() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;

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
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;

    // Right after init: only the sentinel prefill (`0..=genesis_height`) exists,
    // no real manifest — the genesis block never gets one.
    let prefill_count = harness.genesis_height + 1;
    assert_eq!(
        harness.get_mmr_leaf_count() as u64,
        prefill_count,
        "no manifest should be stored before any post-genesis block is processed"
    );

    // The genesis anchor is the latest stored state before any block is mined;
    // assert the manifest store itself holds nothing for it, not merely that its
    // MMR slot is a sentinel.
    let genesis_commitment = harness
        .get_latest_asm_state()
        .unwrap()
        .expect("genesis anchor stored")
        .0;
    assert!(
        harness.get_manifest(&genesis_commitment).is_none(),
        "no manifest should be stored for the genesis block"
    );

    // Mine one block on top of genesis and verify exactly one manifest is
    // stored, at height `genesis_height + 1`.
    let hash = harness
        .mine_block(None)
        .await
        .expect("Failed to mine block");
    let block = harness.commitment_of(hash).await.expect("commitment");

    assert_eq!(
        harness.get_mmr_leaf_count() as u64,
        prefill_count + 1,
        "mining one block should append exactly one manifest leaf"
    );
    let manifest = harness
        .get_manifest(&block)
        .expect("manifest stored for the mined block");
    assert_eq!(
        manifest.height() as u64,
        harness.genesis_height + 1,
        "first stored manifest should be for height `genesis_height + 1`"
    );
}

/// Verifies ASM worker processes multiple mined blocks.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_block_processing() {
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;
    let (l1, state) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(l1, state.chain_view.pow_state.last_verified_block);
    assert_eq!(
        l1.height() as u64,
        state.chain_view.history_accumulator.last_inserted_height()
    );

    let block_hashes = harness.mine_blocks(3).await.expect("Failed to mine blocks");
    assert_eq!(block_hashes.len(), 3);

    let tip_height = harness
        .get_chain_tip()
        .await
        .expect("Failed to get chain tip");
    assert_eq!(tip_height, harness.genesis_height + 3);
    assert_eq!(l1, state.chain_view.pow_state.last_verified_block);
    assert_eq!(
        l1.height() as u64,
        state.chain_view.history_accumulator.last_inserted_height()
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
    let Setup { harness, .. } = AsmTestHarnessBuilder::default().build().await;

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

    // The genesis anchor is the latest stored state before any block is mined;
    // hold onto its commitment to assert the manifest store never gains a
    // genesis entry.
    let genesis_commitment = harness
        .get_latest_asm_state()
        .unwrap()
        .expect("genesis anchor stored")
        .0;

    // Mine blocks in multiple rounds of increasing size to exercise the MMR
    // across different tree shapes (powers of two, odd counts, etc.).
    // The compact MMR's internal peak structure changes at each power-of-two
    // boundary, so we want to cross several of them.
    let rounds: &[usize] = &[1, 3, 4, 8, 16];
    let mut total_blocks_mined: usize = 0;
    // Commitments for every mined block, so the integrity check below can
    // request each block's manifest by block rather than dumping the store.
    let mut mined_commitments = Vec::new();

    for (round, &count) in rounds.iter().enumerate() {
        let block_hashes = harness
            .mine_blocks(count)
            .await
            .unwrap_or_else(|e| panic!("round {round}: failed to mine {count} blocks: {e}"));
        assert_eq!(block_hashes.len(), count);
        total_blocks_mined += count;
        for hash in &block_hashes {
            mined_commitments.push(
                harness
                    .commitment_of(*hash)
                    .await
                    .unwrap_or_else(|e| panic!("round {round}: commitment for {hash}: {e}")),
            );
        }

        // -- Proven (internal) compact MMR --
        let (_commitment, latest_state) = harness
            .get_latest_asm_state()
            .unwrap_or_else(|e| panic!("round {round}: failed to get ASM state: {e}"))
            .unwrap_or_else(|| panic!("round {round}: ASM state should exist"));

        let proven_accumulator = &latest_state.chain_view.history_accumulator;
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
    // manifest hash. Indices `0..=genesis_height` are prefill sentinels.
    let prefill_count = (genesis_height + 1) as usize;

    assert_eq!(
        harness.get_mmr_leaf_count(),
        prefill_count + total_blocks_mined,
        "final external MMR should have {prefill_count} prefill + {total_blocks_mined} real leaves"
    );

    let sentinel = AsmManifestHash::from(L1_HEIGHT_MMR_PREFILL_LEAF);
    for mmr_index in 0..prefill_count as u64 {
        assert_eq!(
            harness.get_manifest_hash(mmr_index).expect("prefill leaf"),
            sentinel,
            "pre-genesis leaf at index {mmr_index} must be the prefill sentinel"
        );
    }

    // Each real leaf must equal the recorded manifest's hash, both fetched by
    // the specific mined block.
    for commitment in &mined_commitments {
        let block_height = commitment.height() as u64;
        let external_leaf_hash = harness
            .get_manifest_hash(block_height)
            .expect("real leaf hash");
        let manifest = harness
            .get_manifest(commitment)
            .unwrap_or_else(|| panic!("no stored manifest for height {block_height}"));

        assert_eq!(
            external_leaf_hash,
            manifest.compute_hash(),
            "leaf hash mismatch at L1 height {block_height}: \
             external MMR disagrees with manifest compute_hash()"
        );
    }

    // The worker stores no manifest for the genesis block: assert its manifest
    // store holds nothing at the genesis commitment. The sentinel prefill loop
    // above independently confirms genesis's MMR slot was never overwritten.
    assert!(
        harness.get_manifest(&genesis_commitment).is_none(),
        "no manifest should be stored for the genesis block"
    );
}

/// A short reorg — onto a branch that is *shorter* than the one it abandons —
/// leaves the durable "latest state" pointer resolving to the taller abandoned
/// branch until the new branch out-heights it.
///
/// The anchor-state store is keyed by block commitment `(height, blkid)`, and
/// "latest" is the highest key. The worker's forward pass only ever appends
/// states (it never prunes an abandoned branch), while the in-memory anchor
/// correctly follows the new branch by walking real parents. So after a reorg to
/// a lower tip, the canonical branch's state is persisted and correct, but every
/// query that reads the height-max latest — `get_latest_asm_state`,
/// `bridge_state`, and what a restarting worker resumes from — still sees the
/// taller abandoned branch. It converges only once the new branch grows strictly
/// past the old tip, at which point height dominates the key ordering.
///
/// Deposits stand in as observable per-branch state; the property under test is
/// the ASM state store's, not the bridge's.
///
/// Flow:
/// 1. Branch A: submit 2 deposits, making A several blocks tall and carrying two deposits in its
///    bridge state.
/// 2. Reorg onto a strictly shorter, empty branch B (which reproduces none of the deposits). The
///    workers follow B, but `latest` still resolves to A.
/// 3. Grow B with empty blocks until it out-heights A. `latest` now tracks B and the stale deposits
///    are gone.
///
/// This pins the current (pre-fix) behavior. STR-3819 tracks closing the
/// divergence window — the worker never prunes orphaned anchors on reorg, so the
/// max-height `latest` pointer can outrank the canonical tip; pruning them (or
/// making the pointer canonical-aware) would collapse it. Update this test when
/// that lands.
#[tokio::test(flavor = "multi_thread")]
async fn test_short_reorg_latest_pointer_diverges_then_converges() {
    let Setup {
        harness,
        bridge: ctx,
        ..
    } = AsmTestHarnessBuilder::default()
        .with_txindex()
        .build()
        .await;

    // The fork point both branches share: the tip before branch A is mined. The
    // first block above it is the first block of branch A.
    let fork_height = harness.get_chain_tip().await.unwrap();

    // 1. Branch A: two deposits make it several blocks tall and give it state.
    harness.submit_deposits(&ctx, 2).await.unwrap();
    let (branch_a_tip, _) = harness.get_latest_asm_state().unwrap().unwrap();
    let branch_a_height = branch_a_tip.height();
    assert_eq!(
        harness.bridge_state().unwrap().deposits().len(),
        2,
        "branch A should carry the two deposits before the reorg",
    );

    // 2. Reorg onto a strictly shorter branch B: invalidate branch A's first block and mine a
    //    single empty block. B reproduces none of the deposits.
    let branch_a_first = harness.block_hash_at(fork_height + 1).await.unwrap();
    let branch_b_tip_hash = harness.reorg(branch_a_first, 1).await.unwrap();
    let branch_b_tip = harness.commitment_of(branch_b_tip_hash).await.unwrap();
    assert!(
        branch_b_tip.height() < branch_a_height,
        "branch B ({}) must be shorter than branch A ({branch_a_height})",
        branch_b_tip.height(),
    );

    // The canonical branch B is persisted and correct — the worker followed it...
    let branch_b_state = harness.get_asm_state_at(&branch_b_tip).unwrap();
    assert!(
        extract_bridge_state(&branch_b_state)
            .unwrap()
            .deposits()
            .is_empty(),
        "branch B reproduces none of the deposits",
    );
    // ...but the height-max latest pointer still resolves to the abandoned branch A.
    let (latest_tip, _) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(
        latest_tip, branch_a_tip,
        "latest still resolves to the taller abandoned branch A after the short reorg",
    );
    assert_eq!(
        harness.bridge_state().unwrap().deposits().len(),
        2,
        "bridge_state, read through latest, still shows branch A's stale deposits",
    );

    // 3. Grow branch B strictly past branch A with empty blocks (excluding the mempool-resurrected
    //    deposits), so height dominates the key ordering.
    let delta = (branch_a_height - branch_b_tip.height() + 1) as usize;
    let grown_tip_hash = harness.mine_empty_blocks(delta).await.unwrap();
    let grown_tip = harness.commitment_of(grown_tip_hash).await.unwrap();
    assert!(
        grown_tip.height() > branch_a_height,
        "branch B ({}) must now out-height branch A ({branch_a_height})",
        grown_tip.height(),
    );

    // Convergence: latest now tracks branch B, and the stale deposits are gone.
    let (latest_tip, _) = harness.get_latest_asm_state().unwrap().unwrap();
    assert_eq!(
        latest_tip, grown_tip,
        "latest converges to branch B once it out-heights the abandoned branch A",
    );
    assert!(
        harness.bridge_state().unwrap().deposits().is_empty(),
        "bridge_state converges to branch B: the abandoned deposits are gone",
    );
}
