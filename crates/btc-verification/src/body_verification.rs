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

        // Check the coinbase inclusion proof.
        if !proof.verify(coinbase, header.merkle_root.to_byte_array().into()) {
            return Err(L1BodyError::InvalidInclusionProof);
        }

        Ok(Buf32::from(witness_root.to_byte_array()))
    } else {
        // If there’s no witness commitment at all, fall back to a merkle root check.
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
        let coinbase_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);
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
        let non_coinbase_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 1);
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

        let valid_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);
        assert!(check_block_integrity(&block, Some(&valid_inclusion_proof)).is_err());
    }

    #[test]
    fn test_block_without_witness_data() {
        let btc_chain = BtcMainnetSegment::load();
        let block = btc_chain.get_block_at(40321).unwrap();

        // Verify with an empty inclusion proof.
        check_block_integrity(&block, None).unwrap();

        // Verify with a valid inclusion proof.
        let valid_inclusion_proof = TxidInclusionProof::generate(&block.txdata, 0);
        check_block_integrity(&block, Some(&valid_inclusion_proof)).unwrap();
    }
}
