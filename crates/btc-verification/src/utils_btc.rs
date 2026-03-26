use std::cmp;

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

/// Computes the [`Txid`] using [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2)
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

/// Computes the [`Wtxid`] using [RustCrypto's SHA-2 crate](https://github.com/RustCrypto/hashes/tree/master/sha2)
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

/// Hashes two 32-byte nodes together (SHA-256d of their concatenation).
fn hash_pair(h1: &Buf32, h2: &Buf32) -> Buf32 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(h1.as_ref());
    buf[32..].copy_from_slice(h2.as_ref());
    sha256d(&buf)
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
pub(crate) fn calculate_root<I>(mut hashes: I) -> Option<Buf32>
where
    I: ExactSizeIterator<Item = Buf32>,
{
    let first = hashes.next()?;
    let second = match hashes.next() {
        Some(second) => second,
        None => return Some(first),
    };

    let alloc_capacity = (hashes.len() + 2) / 2 + 1;
    let mut hashes = [first, second].into_iter().chain(hashes);

    // We need a local copy to pass to `merkle_root_r`. It's more efficient to do the first loop of
    // processing as we make the copy instead of copying the whole iterator.
    let mut alloc = Vec::with_capacity(alloc_capacity);

    while let Some(hash1) = hashes.next() {
        // If the size is odd, use the last element twice.
        let hash2 = hashes.next().unwrap_or(hash1);
        alloc.push(hash_pair(&hash1, &hash2));
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
        let idx2 = cmp::min(idx1 + 1, hashes.len() - 1);
        let (a, b) = (hashes[idx1], hashes[idx2]);
        hashes[idx] = hash_pair(&a, &b);
    }
    let half_len = hashes.len() / 2 + hashes.len() % 2;

    merkle_root_r(&mut hashes[0..half_len])
}

#[cfg(test)]
mod tests {
    use bitcoin::{TxMerkleNode, merkle_tree};
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
            merkle_tree::calculate_root(&mut btc_hashes.into_iter())
                .unwrap()
                .to_byte_array(),
        );
        let actual = calculate_root(hashes.into_iter()).unwrap();
        assert_eq!(expected, actual);
    }
}
