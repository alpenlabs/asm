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
        let witness_root =
            compute_witness_root(txdata).ok_or(L1BodyError::WitnessCommitmentMismatch)?;

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
        if !check_merkle_root(block) {
            return Err(L1BodyError::MerkleRootMismatch);
        }

        Ok(Buf32::from(header.merkle_root.to_byte_array()))
    }
}

/// Computes the transaction merkle root.
///
/// Equivalent to [`compute_merkle_root`](Block::compute_merkle_root)
pub(crate) fn compute_merkle_root(block: &Block) -> Option<TxMerkleNode> {
    let hashes = block
        .txdata
        .iter()
        .map(|tx| Buf32::from(compute_txid(tx).to_byte_array()));
    calculate_root(hashes).map(|root| TxMerkleNode::from_byte_array(root.0))
}

/// Computes the witness root.
///
/// Equivalent to [`witness_root`](Block::witness_root)
pub(crate) fn compute_witness_root(transactions: &[Transaction]) -> Option<WitnessMerkleNode> {
    let hashes = transactions.iter().enumerate().map(|(i, t)| {
        if i == 0 {
            // Replace the first hash with zeroes.
            Buf32::zero()
        } else {
            Buf32::from(compute_wtxid(t).to_byte_array())
        }
    });
    calculate_root(hashes).map(|root| WitnessMerkleNode::from_byte_array(root.0))
}

/// Checks if Merkle root of header matches Merkle root of the transaction list.
///
/// Equivalent to [`check_merkle_root`](Block::check_merkle_root).
pub(crate) fn check_merkle_root(block: &Block) -> bool {
    match compute_merkle_root(block) {
        Some(merkle_root) => {
            block.header.merkle_root == TxMerkleNode::from_byte_array(*merkle_root.as_ref())
        }
        None => false,
    }
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
        assert!(
            check_merkle_root(&block),
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
    /// normal and must keep verifying — mistaking it for a mutated body would halt the ASM on
    /// ordinary mainnet blocks.
    #[test]
    fn test_odd_transaction_counts_accepted() {
        for tx_count in [1, 3, 5, 7, 9, 11] {
            let block = legacy_block(tx_count);
            check_block_integrity(&block, None)
                .unwrap_or_else(|e| panic!("{tx_count} transactions must verify, got {e}"));
        }
    }

    /// Repeating the trailing transactions of a legacy block leaves the merkle root untouched
    /// (CVE-2012-2459), so comparing the root against the header cannot separate the two bodies.
    ///
    /// The block is accepted today. A later commit rejects it.
    #[test]
    fn test_merkle_mutation_accepted_legacy() {
        let block = legacy_block(5);
        check_block_integrity(&block, None).expect("the original block verifies");

        let mutated = mutate(&block);
        assert_eq!(mutated.txdata.len(), 6, "the body grew");
        assert_eq!(
            compute_merkle_root(&mutated).unwrap(),
            block.header.merkle_root,
            "the mutation must not change the merkle root, or it demonstrates nothing"
        );

        assert!(
            check_block_integrity(&mutated, None).is_ok(),
            "known gap: a body Bitcoin rejects is admitted for execution"
        );
    }

    /// The same on the segwit path, which never compares the txid merkle root directly.
    ///
    /// Every check the path does make still passes: the witness root is preserved by the same
    /// duplication, so the coinbase commitment matches, and the tree depth is unchanged, so the
    /// coinbase inclusion proof verifies against the real header.
    ///
    /// The block is accepted today. A later commit rejects it.
    #[test]
    fn test_merkle_mutation_accepted_segwit() {
        let block = BtcMainnetSegment::load_full_block();
        let proof = TxidInclusionProof::generate(&block.txdata, 0).expect("valid index");
        let witness_root =
            check_block_integrity(&block, Some(&proof)).expect("the original block verifies");

        let mutated = mutate(&block);
        assert!(mutated.txdata.len() > block.txdata.len(), "the body grew");
        assert!(
            proof.verify(
                &mutated.txdata[0],
                mutated.header.merkle_root.to_byte_array().into(),
                mutated.txdata.len(),
            ),
            "the mutated body must still satisfy the coinbase inclusion proof"
        );

        assert_eq!(
            check_block_integrity(&mutated, Some(&proof)).ok(),
            Some(witness_root),
            "known gap: the mutated body yields the same witness root and is admitted"
        );
    }
}
