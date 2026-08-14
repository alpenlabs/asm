//! Regression tests for miner-controlled coinbase transactions.
//!
//! A miner picks the coinbase's contents freely: it spends no UTXO and carries
//! no signature, so any SPS-50 tag can be attached to it for the cost of mining
//! a block. The STF therefore skips the coinbase before grouping transactions by
//! subprotocol, and these tests pin that down.

#![allow(
    unused_crate_dependencies,
    reason = "test dependencies shared across test suite"
)]

use bitcoin::{
    block::{Header, Version as BlockVersion},
    hashes::Hash,
    Amount, Block, BlockHash, CompactTarget, Network, OutPoint, ScriptBuf, Transaction,
    TxMerkleNode,
};
use strata_asm_common::{AnchorState, AuxData};
use strata_asm_params::AsmParams;
use strata_asm_proto_bridge_txs::{
    deposit::DepositTxHeaderAux,
    test_utils::{create_dummy_tx, TEST_MAGIC_BYTES},
    BRIDGE_SUBPROTOCOL_ID,
};
use strata_asm_spec::{construct_genesis_state, StrataAsmSpec};
use strata_asm_stf::{compute_asm_transition, pre_process_asm};
use strata_btc_types::BlockHashExt;
use strata_btc_verification::{compute_block_hash, L1Anchor};
use strata_identifiers::L1BlockCommitment;
use strata_l1_txfmt::ParseConfig;
use strata_test_utils_arb::ArbitraryGenerator;

const GENESIS_HEIGHT: u32 = 100;

/// Regtest's easiest target, so the blocks below can be mined in-process.
fn target() -> CompactTarget {
    CompactTarget::from_consensus(0x207f_ffff)
}

/// A genesis anchor state whose chain tip is `parent`, so a block built on
/// `parent` is the next block the STF expects.
fn genesis_state(parent: BlockHash) -> AnchorState {
    let mut params: AsmParams = ArbitraryGenerator::new().generate();
    params.magic = TEST_MAGIC_BYTES;
    params.anchor = L1Anchor {
        block: L1BlockCommitment::new(GENESIS_HEIGHT, parent.to_l1_block_id()),
        next_target: target().to_consensus(),
        epoch_start_timestamp: 0,
        network: Network::Regtest,
    };
    construct_genesis_state(&params)
}

/// Mines a child of `parent` carrying `coinbase` as its only transaction.
fn mine_child_block(parent: BlockHash, coinbase: Transaction) -> Block {
    assert!(coinbase.is_coinbase(), "txdata[0] must be a real coinbase");

    let mut block = Block {
        header: Header {
            version: BlockVersion::ONE,
            prev_blockhash: parent,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1,
            bits: target(),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .expect("one in-memory transaction has a merkle root");

    while !block
        .header
        .target()
        .is_met_by(compute_block_hash(&block.header))
    {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

/// A plain coinbase: null prevout on input 0, no SPS-50 tag.
fn untagged_coinbase() -> Transaction {
    let mut coinbase = create_dummy_tx(1, 2);
    assert_eq!(coinbase.input[0].previous_output, OutPoint::null());
    coinbase.output[1].value = Amount::from_sat(100_000);
    coinbase
}

/// The same coinbase, with a well-formed bridge Deposit tag in output 0.
fn deposit_tagged_coinbase() -> Transaction {
    let mut coinbase = untagged_coinbase();
    let tag = DepositTxHeaderAux::new(7).build_tag_data();
    coinbase.output[0].script_pubkey = ParseConfig::new(TEST_MAGIC_BYTES)
        .encode_script_buf(&tag.as_ref())
        .expect("Deposit SPS-50 tag must encode");
    coinbase.output[1].script_pubkey = ScriptBuf::new();
    coinbase
}

/// A Deposit-tagged coinbase must not reach the bridge subprotocol.
///
/// The deposit parser reads input 0's prevout as the DRT reference and the
/// bridge asks the worker to fetch that transaction. A coinbase's input 0 is the
/// null outpoint, so routing it to the bridge would make the worker fetch a txid
/// that cannot exist. That fetch has no fallback: it fails the block's
/// transition and shuts the worker down, deterministically, for every node. So
/// any miner could halt the network with a single block.
#[test]
fn tagged_coinbase_is_ignored_by_the_stf() {
    let parent = BlockHash::all_zeros();
    let genesis = genesis_state(parent);

    // Control: an untagged coinbase requests nothing and transitions cleanly.
    let untagged = mine_child_block(parent, untagged_coinbase());
    let control = pre_process_asm(&StrataAsmSpec, &genesis, &untagged)
        .expect("valid untagged child block preprocesses");
    assert!(control.aux_requests.bitcoin_txs().is_empty());
    compute_asm_transition(
        &StrataAsmSpec,
        &genesis,
        &untagged,
        &AuxData::default(),
        None,
    )
    .expect("valid untagged child block completes its transition");

    // Attack: the miner puts a valid bridge Deposit tag on the coinbase.
    let malicious = mine_child_block(parent, deposit_tagged_coinbase());
    let preprocessed = pre_process_asm(&StrataAsmSpec, &genesis, &malicious)
        .expect("a tagged coinbase does not fail preprocessing");

    assert!(
        !preprocessed.txs.contains_key(&BRIDGE_SUBPROTOCOL_ID),
        "a tagged coinbase must not be routed to the bridge subprotocol",
    );
    assert!(
        preprocessed.aux_requests.bitcoin_txs().is_empty(),
        "a tagged coinbase must not make the worker fetch the null txid",
    );

    // With nothing requested, the block transitions on empty aux data instead of
    // stalling the worker on an unresolvable fetch.
    compute_asm_transition(
        &StrataAsmSpec,
        &genesis,
        &malicious,
        &AuxData::default(),
        None,
    )
    .expect("a block with a tagged coinbase still completes its transition");
}
