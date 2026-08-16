//! Block body verification.
//!
//! # Scope
//!
//! The ASM is not a Bitcoin validator. It does not check scripts, signatures, fees, value
//! conservation, or double spends. Proof of work authenticates the *header*, and the header is
//! trusted only for what it commits to.
//!
//! What this module enforces is correspondingly narrow: the rules that make a header a binding
//! commitment to one body, plus the rules that make transaction identity well defined. That set is
//! closed, and all of it is enforced here:
//!
//! - No duplicate transactions, without which a merkle root does not identify one transaction list
//!   (CVE-2012-2459). See [`calculate_root_no_dups`].
//! - No witness data unless the coinbase commits to it, since the txid merkle root does not cover
//!   witness data (BIP141). See [`L1BodyError::UncommittedWitnessData`].
//! - No internal merkle node passed off as a leaf, excluded by pinning proof length to the tree
//!   depth in [`TxidInclusionProof::verify`].
//!
//! Rules outside that set are left to Bitcoin: breaking one means mining a block the network then
//! orphans, so it reaches the ASM only as part of a chain that out-mines the honest one. Duplicate
//! transactions are the exception, and the reason they appear above — a body mutated that way
//! reuses the header it came with, so it carries the same accumulated work as the honest body and
//! no comparison of chains separates them.

use bitcoin::{
    Block, Transaction, TxMerkleNode, WitnessCommitment, WitnessMerkleNode, consensus::Encodable,
    hashes::Hash,
};
use strata_crypto::hash::sha256d;
use strata_identifiers::Buf32;

use crate::{
    compute_txid, compute_wtxid, errors::L1BodyError, inclusion_proof::TxidInclusionProof,
    utils_btc::calculate_root,
};

/// Checks the integrity of a block using the provided coinbase inclusion proof.
///
/// We pass the `inclusion_proof` for the coinbase transaction to avoid recalculating
/// the entire Merkle root for verifying coinbase inclusion. This optimization
/// simplifies the verification logic and improves performance, for blocks containing SegWit
/// transactions.
///
/// This function applies different validation paths depending on whether the block
/// includes segwit transactions:
///
/// 1. **Blocks with segwit transactions**
///    - Verifies that the witness commitment in the coinbase transaction matches the aggregated
///      witness data of the block’s segwit transactions.
///    - Checks the coinbase transaction’s inclusion in the block’s Merkle tree using the provided
///      `inclusion_proof`.
///
/// 2. **Blocks without segwit transactions**
///    - Validates the Merkle root by comparing the block header’s Merkle root with the Merkle root
///      computed from all transactions.
///
/// # Returns
///
/// On success, returns the witness transaction IDs Merkle root (`Buf32`) for SegWit blocks,
/// or the transaction Merkle root for non-SegWit blocks. For blocks without witness data
/// (pre-SegWit or legacy-only transactions), the witness Merkle root equals the transaction
/// Merkle root per Bitcoin protocol. This avoids recomputing the root downstream.
///
/// # Errors
///
/// Returns a [`L1BodyError`] if any of the integrity checks fail.
pub fn check_block_integrity(
    block: &Block,
    coinbase_inclusion_proof: Option<&TxidInclusionProof>,
) -> Result<Buf32, L1BodyError> {
    let Block { header, txdata } = block;
    if txdata.is_empty() {
        return Err(L1BodyError::EmptyBlock);
    }

    let coinbase = &txdata[0];
    if !coinbase.is_coinbase() {
        return Err(L1BodyError::NotCoinbase);
    }

    if let Some(commitment) = witness_commitment_from_coinbase(coinbase) {
        // If we have a witness commitment, we also need an inclusion proof.
        let proof = match coinbase_inclusion_proof {
            Some(proof) => proof,
            None => return Err(L1BodyError::MissingInclusionProof),
        };

        // Gather the witness data; it must have exactly one element of length 32 bytes.
        let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
        if witness_vec.len() != 1 || witness_vec[0].len() != 32 {
            return Err(L1BodyError::InvalidCoinbaseWitness);
        }

        // Compute the witness root once and reuse it for both the commitment check and return.
        let witness_root = compute_witness_root(txdata)?;

        // Verify the witness commitment using the computed witness root.
        let mut vec = vec![];
        witness_root
            .consensus_encode(&mut vec)
            .expect("engines don’t error");
        vec.extend(witness_vec[0]);
        let computed_commitment = WitnessCommitment::from_byte_array(*sha256d(&vec).as_ref());
        if commitment != computed_commitment {
            return Err(L1BodyError::WitnessCommitmentMismatch);
        }

        // Check the coinbase inclusion proof. The transaction count comes from the block body,
        // binding the proof to the block's actual Merkle tree.
        if !proof.verify(
            coinbase,
            header.merkle_root.to_byte_array().into(),
            txdata.len(),
        ) {
            return Err(L1BodyError::InvalidInclusionProof);
        }

        Ok(Buf32::from(witness_root.to_byte_array()))
    } else {
        // The merkle root commits only to txids, which exclude witness data, so it cannot detect
        // witness attached to a commitment-free block. Enforce the BIP141 rule explicitly: reject
        // any block that omits the commitment yet carries witness data. Without this, a tampered
        // witness-free block could smuggle arbitrary uncommitted witness past body verification.
        let has_witness = txdata
            .iter()
            .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()));
        if has_witness {
            return Err(L1BodyError::UncommittedWitnessData);
        }

        // No witness commitment in the coinbase. Per BIP141 the commitment may be omitted only
        // when *no* transaction carries witness data, so validate the header's merkle root against
        // the txids.
        if compute_merkle_root(block)? != header.merkle_root {
            return Err(L1BodyError::MerkleRootMismatch);
        }

        Ok(Buf32::from(header.merkle_root.to_byte_array()))
    }
}

/// Computes a merkle root over `hashes`, rejecting duplicate leaves.
///
/// Bitcoin's merkle tree duplicates the last node of any odd-sized level, so a transaction list
/// that repeats its trailing entries produces the same root as the list without them
/// (CVE-2012-2459). A merkle root therefore does not identify one transaction list, and a header
/// does not bind a body, until duplicates are excluded.
///
/// Duplicates are detected at the leaves. Two equal nodes higher up mean two equal subtrees, hence
/// duplicate leaves beneath them, so a leaf scan covers every level. Bitcoin Core instead flags
/// equal sibling pairs as it walks the tree. Checking here rather than in [`calculate_root`] keeps
/// that function a faithful port of its rust-bitcoin counterpart, which has no such check.
///
/// The leaves are sorted before the scan. A repeated subtree of width `w` places its copies `w`
/// apart, so neighbours in block order reveal only the `w == 1` case.
///
/// Callers pass different leaves: txids on the legacy path, wtxids on the segwit path. Either
/// identifies a repeated transaction. A pair sharing a txid but not a wtxid is invisible to the
/// wtxid leaves; the differing wtxid moves the witness root, so the commitment check rejects it
/// instead.
///
/// # Returns
///
/// The merkle root over `hashes`, in the order given.
///
/// # Errors
///
/// Returns [`L1BodyError::DuplicateTransaction`] if any leaf repeats, or
/// [`L1BodyError::EmptyBlock`] if `hashes` is empty.
fn calculate_root_no_dups<I>(hashes: I) -> Result<Buf32, L1BodyError>
where
    I: ExactSizeIterator<Item = Buf32>,
{
    let mut leaves: Vec<Buf32> = hashes.collect();

    // Take the root before sorting; the merkle root depends on the block's own ordering.
    let root = calculate_root(leaves.iter().copied()).ok_or(L1BodyError::EmptyBlock)?;

    leaves.sort_unstable();
    if leaves.windows(2).any(|w| w[0] == w[1]) {
        return Err(L1BodyError::DuplicateTransaction);
    }

    Ok(root)
}

/// Computes the transaction merkle root.
///
/// Equivalent to [`compute_merkle_root`](Block::compute_merkle_root), except that duplicate
/// transactions are rejected. See [`calculate_root_no_dups`].
pub(crate) fn compute_merkle_root(block: &Block) -> Result<TxMerkleNode, L1BodyError> {
    let hashes = block
        .txdata
        .iter()
        .map(|tx| Buf32::from(compute_txid(tx).to_byte_array()));
    calculate_root_no_dups(hashes).map(|root| TxMerkleNode::from_byte_array(root.0))
}

/// Computes the witness root.
///
/// Equivalent to [`witness_root`](Block::witness_root), except that duplicate transactions are
/// rejected. See [`calculate_root_no_dups`].
pub(crate) fn compute_witness_root(
    transactions: &[Transaction],
) -> Result<WitnessMerkleNode, L1BodyError> {
    let hashes = transactions.iter().enumerate().map(|(i, t)| {
        if i == 0 {
            // Replace the first hash with zeroes.
            Buf32::zero()
        } else {
            Buf32::from(compute_wtxid(t).to_byte_array())
        }
    });
    calculate_root_no_dups(hashes).map(|root| WitnessMerkleNode::from_byte_array(root.0))
}

/// Scans the given coinbase transaction for a witness commitment and returns it if found.
///
/// This function iterates over the outputs of the provided `coinbase` transaction from the end
/// towards the beginning, looking for an output whose `script_pubkey` starts with the "magic" bytes
/// `[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]`. This pattern indicates an `OP_RETURN` with an
/// embedded witness commitment header. If such an output is found, the function extracts the
/// following 32 bytes as the witness commitment and returns a [`WitnessCommitment`].
///
/// Based on: [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin/blob/b97be3d4974d40cf348b280718d1367b8148d1ba/bitcoin/src/blockdata/block.rs#L190-L210).
pub(crate) fn witness_commitment_from_coinbase(
    coinbase: &Transaction,
) -> Option<WitnessCommitment> {
    // Consists of OP_RETURN, OP_PUSHBYTES_36, and four "witness header" bytes.
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

    // Commitment is in the last output that starts with magic bytes.
    if let Some(pos) = coinbase
        .output
        .iter()
        .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
    {
        let bytes =
            <[u8; 32]>::try_from(&coinbase.output[pos].script_pubkey.as_bytes()[6..38]).unwrap();
        Some(WitnessCommitment::from_byte_array(bytes))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Witness;
    use strata_test_utils_btc::BtcMainnetSegment;

    use super::*;

    #[test]
    fn test_block_with_valid_witness() {
        let block = BtcMainnetSegment::load_full_block();
        let coinbase_inclusion_proof =
            TxidInclusionProof::generate(&block.txdata, 0).expect("valid index");
        check_block_integrity(&block, Some(&coinbase_inclusion_proof)).unwrap();
    }

    #[test]
    fn test_block_with_invalid_coinbase_inclusion_proof() {
        let block = BtcMainnetSegment::load_full_block();
        let err = check_block_integrity(&block, None).unwrap_err();
        assert!(matches!(err, L1BodyError::MissingInclusionProof));
    }

    #[test]
    fn test_block_with_valid_inclusion_proof_of_other_tx() {
        let block = BtcMainnetSegment::load_full_block();
        let non_coinbase_inclusion_proof =
            TxidInclusionProof::generate(&block.txdata, 1).expect("valid index");
        let err = check_block_integrity(&block, Some(&non_coinbase_inclusion_proof)).unwrap_err();
        assert!(matches!(err, L1BodyError::InvalidInclusionProof));
    }

    #[test]
    fn test_block_with_witness_removed() {
        let mut block = BtcMainnetSegment::load_full_block();
        let empty_witness = Witness::new();

        // Remove witness data from all transactions.
        for tx in &mut block.txdata {
            for input in &mut tx.input {
                input.witness = empty_witness.clone();
            }
        }

        assert!(check_block_integrity(&block, None).is_err());
    }

    #[test]
    fn test_block_with_removed_witness_but_valid_inclusion_proof() {
        let mut block = BtcMainnetSegment::load_full_block();
        let empty_witness = Witness::new();

        // Remove witness data from all transactions.
        for tx in &mut block.txdata {
            for input in &mut tx.input {
                input.witness = empty_witness.clone();
            }
        }

        let valid_inclusion_proof =
            TxidInclusionProof::generate(&block.txdata, 0).expect("valid index");
        assert!(check_block_integrity(&block, Some(&valid_inclusion_proof)).is_err());
    }

    #[test]
    fn test_block_without_witness_data() {
        let btc_chain = BtcMainnetSegment::load();
        let block = btc_chain.get_block_at(40321).unwrap();

        // Verify with an empty inclusion proof.
        check_block_integrity(&block, None).unwrap();

        // Verify with a valid inclusion proof.
        let valid_inclusion_proof =
            TxidInclusionProof::generate(&block.txdata, 0).expect("valid index");
        check_block_integrity(&block, Some(&valid_inclusion_proof)).unwrap();
    }

    /// A block whose coinbase omits the witness commitment but that still carries witness data must
    /// be rejected. This is the combination BIP141 forbids: the commitment may be omitted only for
    /// fully witness-free blocks. Because txids exclude witness data, attaching witness to a legacy
    /// block leaves the header's merkle root valid, so the merkle check alone cannot catch it — the
    /// explicit `UncommittedWitnessData` guard must.
    #[test]
    fn test_uncommitted_witness_data_rejected() {
        let btc_chain = BtcMainnetSegment::load();
        let mut block = btc_chain.get_block_at(40321).unwrap();

        // This legacy block has no witness commitment and verifies as-is.
        assert!(witness_commitment_from_coinbase(&block.txdata[0]).is_none());
        check_block_integrity(&block, None).unwrap();

        // Attach uncommitted witness data to a transaction input.
        let mut witness = Witness::new();
        witness.push([0x42u8; 32]);
        block.txdata[0].input[0].witness = witness;

        // The merkle root still matches (txids are unchanged by witness edits)...
        assert_eq!(
            compute_merkle_root(&block).unwrap(),
            block.header.merkle_root,
            "witness edits must not change the txid merkle root"
        );

        // ...yet the block must be rejected because the witness is uncommitted.
        let err = check_block_integrity(&block, None).unwrap_err();
        assert!(matches!(err, L1BodyError::UncommittedWitnessData));
    }

    /// Number of trailing transactions to repeat so that the merkle root does not change.
    ///
    /// Bitcoin duplicates the last node of any odd-sized level, so repeating the subtree that sits
    /// under that node reproduces the level exactly. The subtree at level `l` spans `2^l`
    /// transactions, so the answer is `2^l` for the lowest odd level `l`.
    fn mutation_width(tx_count: usize) -> usize {
        let mut width = 1;
        let mut level = tx_count;
        while level > 1 {
            if !level.is_multiple_of(2) {
                return width;
            }
            level /= 2;
            width *= 2;
        }
        panic!("every level of a {tx_count}-transaction tree is even; cannot mutate");
    }

    /// Repeats the last `mutation_width` transactions of `block`, leaving its merkle root intact.
    fn mutate(block: &Block) -> Block {
        let mut mutated = block.clone();
        let width = mutation_width(block.txdata.len());
        mutated
            .txdata
            .extend_from_within(block.txdata.len() - width..);
        mutated
    }

    /// Builds a witness-free block of `tx_count` distinct transactions with a correct merkle root.
    ///
    /// The mainnet fixtures are either a single segwit block or coinbase-only blocks, so the legacy
    /// path needs a block built by hand.
    fn legacy_block(tx_count: usize) -> Block {
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
            absolute::LockTime,
            block::{Header, Version},
            transaction,
        };

        let txdata: Vec<Transaction> = (0..tx_count)
            .map(|i| Transaction {
                version: transaction::Version::TWO,
                // Vary the lock time so every transaction has a distinct txid.
                lock_time: LockTime::from_height(i as u32).unwrap(),
                input: vec![TxIn {
                    // A null prevout is what makes the first transaction a coinbase; the rest get
                    // a distinct one so they are not coinbases themselves.
                    previous_output: if i == 0 {
                        OutPoint::null()
                    } else {
                        OutPoint::new(bitcoin::Txid::from_byte_array([i as u8; 32]), 0)
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                }],
            })
            .collect();

        let merkle_root = {
            let hashes = txdata
                .iter()
                .map(|tx| Buf32::from(compute_txid(tx).to_byte_array()));
            TxMerkleNode::from_byte_array(calculate_root(hashes).unwrap().0)
        };

        Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
                merkle_root,
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00_ffff),
                nonce: 0,
            },
            txdata,
        }
    }

    /// Bitcoin's own tree duplicates the last node of an odd-sized level. That duplication is
    /// normal and must not be mistaken for a mutated body — if it were, the ASM would halt on
    /// ordinary mainnet blocks, which is worse than the bug this check exists to catch.
    #[test]
    fn test_odd_transaction_counts_accepted() {
        for tx_count in [1, 3, 5, 7, 9, 11] {
            let block = legacy_block(tx_count);
            check_block_integrity(&block, None)
                .unwrap_or_else(|e| panic!("{tx_count} transactions must verify, got {e}"));
        }
    }

    /// CVE-2012-2459 on the legacy path: repeating the trailing transactions leaves the merkle root
    /// untouched, so the root check cannot tell the mutated body from the honest one.
    #[test]
    fn test_merkle_mutation_rejected_legacy() {
        let block = legacy_block(5);
        check_block_integrity(&block, None).expect("the honest block verifies");

        let mutated = mutate(&block);
        assert_eq!(mutated.txdata.len(), 6, "the body grew");

        // The premise of the attack: the header still commits to the mutated body, so nothing
        // about the root gives it away.
        let unchecked_root = {
            let hashes = mutated
                .txdata
                .iter()
                .map(|tx| Buf32::from(compute_txid(tx).to_byte_array()));
            TxMerkleNode::from_byte_array(calculate_root(hashes).unwrap().0)
        };
        assert_eq!(
            unchecked_root, block.header.merkle_root,
            "the mutation must not change the merkle root, or this test proves nothing"
        );

        // Which leaves the duplicate check as the only thing that can reject it.
        let err = check_block_integrity(&mutated, None).unwrap_err();
        assert!(matches!(err, L1BodyError::DuplicateTransaction), "{err}");
    }

    /// The same attack on the segwit path, which never compares the txid merkle root directly.
    ///
    /// Every other check still passes on the mutated body — the witness commitment matches and the
    /// coinbase inclusion proof verifies against the real header — so the duplicate check is the
    /// only thing standing between the ASM and a body Bitcoin would reject.
    #[test]
    fn test_merkle_mutation_rejected_segwit() {
        let block = BtcMainnetSegment::load_full_block();
        let proof = TxidInclusionProof::generate(&block.txdata, 0).expect("valid index");
        check_block_integrity(&block, Some(&proof)).expect("the honest block verifies");

        let mutated = mutate(&block);
        assert!(mutated.txdata.len() > block.txdata.len(), "the body grew");

        // The coinbase inclusion proof is unchanged and still verifies at the new transaction
        // count: the mutation leaves the tree depth alone, because an odd node count is never a
        // power of two.
        assert!(
            proof.verify(
                &mutated.txdata[0],
                mutated.header.merkle_root.to_byte_array().into(),
                mutated.txdata.len(),
            ),
            "the mutated body must still satisfy the coinbase inclusion proof"
        );

        let err = check_block_integrity(&mutated, Some(&proof)).unwrap_err();
        assert!(matches!(err, L1BodyError::DuplicateTransaction), "{err}");
    }
}
