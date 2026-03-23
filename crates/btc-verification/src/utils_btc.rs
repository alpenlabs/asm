use bitcoin::{
    BlockHash, Transaction, Txid, Wtxid, block::Header, consensus::Encodable, hashes::Hash,
};
use strata_crypto::hash::sha256d;

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

#[cfg(test)]
mod tests {
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
}
