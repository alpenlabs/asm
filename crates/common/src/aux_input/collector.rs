//! Auxiliary request collector.
//!
//! Collects auxiliary data requests from subprotocols during the pre-processing phase.

use bitcoin::Txid;

use crate::{
    aux_input::data::{AuxRequests, ManifestHashRange},
    logging,
};

/// Collects auxiliary data requests from subprotocols.
///
/// During `pre_process_txs`, subprotocols use this collector to register
/// their auxiliary data requirements (manifest hashes and Bitcoin transactions).
///
/// Requests are collected as-is, duplicates and all. Resolving them is what
/// costs — a lookup per txid, a lookup and an MMR proof per height — and the
/// resolved data ends up keyed by txid and height regardless, so deduplication
/// belongs at resolution rather than here.
#[derive(Debug)]
pub struct AuxRequestCollector {
    requests: AuxRequests,
    /// Highest L1 height whose manifest can be resolved. There is no lower
    /// bound: the MMR is height-indexed and sentinel-prefilled at and before
    /// genesis, so every index down to 0 is a verifiable position.
    ///
    /// Requests above the bound are dropped with a warning rather than rejected,
    /// so an L1 transaction claiming a beyond-tip height cannot fail resolution
    /// and block processing of the whole L1 block. Dropping is not free: the
    /// process phase still runs, and panics if it asks for a height that was
    /// never resolved. The caller must pass a bound that covers every height a
    /// subprotocol can legitimately ask for.
    max_resolvable_manifest_height: u64,
}

impl AuxRequestCollector {
    /// Creates a new empty collector that admits manifest requests up to
    /// `max_resolvable_manifest_height`.
    pub fn new(max_resolvable_manifest_height: u64) -> Self {
        Self {
            requests: AuxRequests::default(),
            max_resolvable_manifest_height,
        }
    }

    /// Requests manifest hashes for a block height range.
    ///
    /// # Arguments
    /// * `start_height` - Starting L1 block height (inclusive)
    /// * `end_height` - Ending L1 block height (inclusive)
    pub fn request_manifest_hashes(&mut self, start_height: u64, end_height: u64) {
        if start_height > end_height || end_height > self.max_resolvable_manifest_height {
            logging::warn!(
                start_height,
                end_height,
                self.max_resolvable_manifest_height,
                "dropping out-of-bounds manifest hash request"
            );
            return;
        }

        self.requests
            .manifest_hashes
            .push(ManifestHashRange::new(start_height, end_height));
    }

    /// Requests a raw Bitcoin transaction by its txid.
    pub fn request_bitcoin_tx(&mut self, txid: Txid) {
        self.requests.bitcoin_txs.push(txid.into());
    }

    /// Consumes the collector and returns the collected auxiliary requests.
    pub fn into_requests(self) -> AuxRequests {
        self.requests
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    #[test]
    fn test_collector_basic() {
        let mut collector = AuxRequestCollector::new(500);
        assert!(collector.requests.manifest_hashes.is_empty());
        assert!(collector.requests.bitcoin_txs.is_empty());

        collector.request_manifest_hashes(100, 200);
        assert_eq!(collector.requests.manifest_hashes.len(), 1);

        collector.request_manifest_hashes(201, 300);
        assert_eq!(collector.requests.manifest_hashes.len(), 2);

        let requests = collector.into_requests();
        assert_eq!(requests.manifest_hashes.len(), 2);
        assert_eq!(requests.manifest_hashes[0].start_height(), 100);
        assert_eq!(requests.manifest_hashes[0].end_height(), 200);
        assert_eq!(requests.manifest_hashes[1].start_height(), 201);
        assert_eq!(requests.manifest_hashes[1].end_height(), 300);
    }

    #[test]
    fn test_collector_drops_beyond_max_height() {
        let mut collector = AuxRequestCollector::new(200);

        collector.request_manifest_hashes(100, 200);
        assert_eq!(collector.requests.manifest_hashes.len(), 1);

        // end_height > max_resolvable_manifest_height: silently dropped
        collector.request_manifest_hashes(100, 201);
        assert_eq!(collector.requests.manifest_hashes.len(), 1);
    }

    /// There is no lower bound. Pre-genesis heights are sentinel positions in the
    /// height-indexed MMR, so they resolve rather than failing the resolver.
    #[test]
    fn test_collector_admits_height_zero() {
        let mut collector = AuxRequestCollector::new(500);

        collector.request_manifest_hashes(0, 200);
        assert_eq!(collector.requests.manifest_hashes.len(), 1);
    }

    #[test]
    fn test_collector_drops_inverted_range() {
        let mut collector = AuxRequestCollector::new(500);

        // start > end: silently dropped
        collector.request_manifest_hashes(200, 100);
        assert!(collector.requests.manifest_hashes.is_empty());
    }

    #[test]
    fn test_collector_bitcoin_tx() {
        let mut collector = AuxRequestCollector::new(500);

        let txid1 = Txid::from_byte_array([1u8; 32]);
        let txid2 = Txid::from_byte_array([2u8; 32]);
        collector.request_bitcoin_tx(txid1);
        collector.request_bitcoin_tx(txid2);

        assert_eq!(collector.requests.bitcoin_txs.len(), 2);

        let requests = collector.into_requests();
        assert_eq!(requests.bitcoin_txs[0], txid1.into());
        assert_eq!(requests.bitcoin_txs[1], txid2.into());
    }
}
