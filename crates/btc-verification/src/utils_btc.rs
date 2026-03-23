use std::iter;

use bitcoin::{
    BlockHash, Transaction, Txid, Wtxid, block::Header, consensus::Encodable, hashes::Hash,
};
use strata_crypto::hash::sha256d;
use strata_identifiers::Buf32;

/// Returns the block hash.
///
/// Equivalent to [`compute_block_hash`](Header::block_hash)
/// but internally uses [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2),
/// because it has patches available from both
/// [Risc0](https://github.com/risc0/RustCrypto-hashes)
/// and [Sp1](https://github.com/sp1-patches/RustCrypto-hashes)
pub fn compute_block_hash(header: &Header) -> BlockHash {
    let mut buf = [0u8; 80];
    let mut writer = &mut buf[..];
    header
        .consensus_encode(&mut writer)
        .expect("engines don't error");
    BlockHash::from_byte_array(sha256d(&buf).0)
}

/// Computes the [`Txid`](bitcoin::Txid) using [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2)
/// for the underlying `sha256d` hash function.
///
/// Equivalent to [`compute_txid`](bitcoin::Transaction::compute_txid)
///
/// This function hashes the transaction **excluding** the segwit data (i.e., the marker, flag
/// bytes, and the witness fields themselves). For non-segwit transactions, which do not have any
/// segwit data, this will be equal to [`compute_wtxid`].
pub fn compute_txid(tx: &Transaction) -> Txid {
    let mut vec = Vec::new();

    tx.version.consensus_encode(&mut vec).unwrap();
    tx.input.consensus_encode(&mut vec).unwrap();
    tx.output.consensus_encode(&mut vec).unwrap();
    tx.lock_time.consensus_encode(&mut vec).unwrap();

    Txid::from_byte_array(sha256d(&vec).0)
}

/// Computes the segwit version of the transaction id using [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2)
///
/// Equivalent to [`compute_wtxid`](bitcoin::Transaction::compute_wtxid)
///
/// Hashes the transaction **including** all segwit data (i.e. the marker, flag bytes, and the
/// witness fields themselves). For non-segwit transactions which do not have any segwit data,
/// this will be equal to [`compute_txid`].
pub fn compute_wtxid(tx: &Transaction) -> Wtxid {
    let mut vec = Vec::new();
    tx.consensus_encode(&mut vec).expect("engines don't error");
    Wtxid::from_byte_array(sha256d(&vec).0)
}

/// Calculates the merkle root of an iterator of *hashes* using [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2).
///
/// Equivalent to [`calculate_root`](bitcoin::merkle_tree::calculate_root)
///
/// # Returns
///
/// - `None` if `hashes` is empty. The merkle root of an empty tree of hashes is undefined.
/// - `Some(hash)` if `hashes` contains one element. A single hash is by definition the merkle root.
/// - `Some(merkle_root)` if length of `hashes` is greater than one.
pub fn calculate_root<I>(mut hashes: I) -> Option<Buf32>
where
    I: Iterator<Item = Buf32>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first),
    };

    let mut hashes = iter::once(first).chain(iter::once(second)).chain(hashes);

    // We need a local copy to pass to `merkle_root_r`. It's more efficient to do the first loop of
    // processing as we make the copy instead of copying the whole iterator.
    let (min, max) = hashes.size_hint();
    let mut alloc = Vec::with_capacity(max.unwrap_or(min) / 2 + 1);

    while let Some(hash1) = hashes.next() {
        // If the size is odd, use the last element twice.
        let hash2 = hashes.next().unwrap_or(hash1);
        let mut vec = Vec::with_capacity(64);
        hash1.as_ref().consensus_encode(&mut vec).unwrap(); // in-memory writers fon't error
        hash2.as_ref().consensus_encode(&mut vec).unwrap(); // in-memory writers don't error

        alloc.push(sha256d(&vec));
    }

    Some(merkle_root_r(&mut alloc))
}

/// Recursively computes the Merkle root from a list of hashes.
///
/// `hashes` must contain at least one hash.
fn merkle_root_r(hashes: &mut [Buf32]) -> Buf32 {
    if hashes.len() == 1 {
        return hashes[0];
    }

    for idx in 0..hashes.len().div_ceil(2) {
        let idx1 = 2 * idx;
        let idx2 = std::cmp::min(idx1 + 1, hashes.len() - 1);
        let mut vec = Vec::with_capacity(64);
        hashes[idx1].as_ref().consensus_encode(&mut vec).unwrap(); // in-memory writers don't error")
        hashes[idx2].as_ref().consensus_encode(&mut vec).unwrap(); // in-memory writers don't error")
        hashes[idx] = sha256d(&vec)
    }
    let half_len = hashes.len() / 2 + hashes.len() % 2;

    merkle_root_r(&mut hashes[0..half_len])
}

#[cfg(test)]
mod tests {
    use bitcoin::TxMerkleNode;
    use rand::Rng;
    use strata_test_utils_btc::BtcMainnetSegment;

    use super::*;

    #[test]
    fn test_compute_block_hash() {
        let btc_block = BtcMainnetSegment::load_full_block();
        assert_eq!(
            compute_block_hash(&btc_block.header),
            btc_block.block_hash()
        );
    }

    #[test]
    fn test_txid() {
        let block = BtcMainnetSegment::load_full_block();
        for tx in &block.txdata {
            assert_eq!(tx.compute_txid(), compute_txid(tx))
        }
    }

    #[test]
    fn test_wtxid() {
        let block = BtcMainnetSegment::load_full_block();
        for tx in &block.txdata {
            assert_eq!(tx.compute_wtxid(), compute_wtxid(tx))
        }
    }

    #[test]
    fn test_merkle_root() {
        let mut rng = rand::thread_rng();
        let n = rng.gen_range(1..1_000);
        let mut btc_hashes = Vec::with_capacity(n);
        let mut hashes = Vec::with_capacity(n);

        for _ in 0..n {
            let random_bytes: [u8; 32] = rng.r#gen();
            btc_hashes.push(TxMerkleNode::from_byte_array(random_bytes));
            let hash = Buf32::from(random_bytes);
            hashes.push(hash);
        }

        let expected = Buf32::from(
            bitcoin::merkle_tree::calculate_root(&mut btc_hashes.into_iter())
                .unwrap()
                .to_byte_array(),
        );
        let actual = calculate_root(&mut hashes.into_iter()).unwrap();
        assert_eq!(expected, actual);
    }
}
