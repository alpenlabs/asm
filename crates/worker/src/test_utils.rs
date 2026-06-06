//! Test utilities for the ASM worker.
//!
//! Provides [`TestAsmWorkerContext`], a [`WorkerContext`](crate::WorkerContext)
//! implementation backed by a Bitcoin regtest node (for L1 data) and in-memory
//! stores (for anchor state, the manifest-hash MMR, and aux data). The worker's
//! own unit tests use it via `cfg(test)`; downstream integration tests pull it in
//! with the `test-utils` feature.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bitcoin::{Block, BlockHash, Network, Txid, block::Header, params::Params};
use bitcoind_async_client::{Client, traits::Reader};
use strata_asm_common::{AsmManifest, AsmManifestHash};
use strata_btc_types::{BitcoinTxid, BlockHashExt, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_btc_verification::{L1Anchor, get_relative_difficulty_adjustment_height};
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_merkle::{MerkleProofB32, Sha256Hasher};
use strata_merkle_node_store::{MemMmr, StoredMmr};
use tokio::{runtime::Handle, task::block_in_place};

use crate::{
    AnchorStateStore, AsmState, AuxDataStore, L1DataProvider, ManifestMmrStore, WorkerError,
    WorkerResult,
};

/// Shared mutable state for the test worker context.
///
/// Consolidating these fields lets us hold a single `Arc<Mutex<_>>` instead of
/// one per field, and keeps related state (the manifest MMR, manifests in
/// insertion order) close together.
#[derive(Debug, Default)]
pub struct TestWorkerStateInner {
    /// ASM states indexed by L1 block commitment
    pub asm_states: HashMap<L1BlockCommitment, AsmState>,
    /// Latest ASM state
    pub latest_asm_state: Option<(L1BlockCommitment, AsmState)>,
    /// Height-indexed manifest-hash MMR. A full node store, so inclusion proofs
    /// come straight from stored nodes in `O(log n)`. The leading entries are
    /// sentinel-prefill for L1 heights up to genesis; real manifest hashes
    /// follow.
    pub manifest_mmr: MemMmr<[u8; 32]>,
    /// Stored manifests in insertion order
    pub manifests: Vec<AsmManifest>,
}

/// Test implementation of WorkerContext for integration tests
///
/// Integrates with local regtest node via RPC client.
#[derive(Clone, Debug)]
pub struct TestAsmWorkerContext {
    /// Bitcoin RPC client for fetching blocks
    pub client: Arc<Client>,
    /// Tokio runtime handle from the test runtime, used for async operations
    /// from the worker's dedicated OS thread (which has no tokio context).
    pub tokio_handle: Handle,
    /// Consolidated shared mutable state.
    pub inner: Arc<Mutex<TestWorkerStateInner>>,
}

impl TestAsmWorkerContext {
    /// Create a new test context with a Bitcoin RPC client.
    ///
    /// Captures the current tokio runtime handle so the worker's dedicated OS
    /// thread can drive async operations on the original runtime (where the
    /// HTTP client's connection pool lives).
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
            tokio_handle: Handle::current(),
            inner: Arc::new(Mutex::new(TestWorkerStateInner::default())),
        }
    }

    /// Number of leaves in the manifest MMR (sentinels + real manifest hashes).
    pub fn mmr_leaf_count(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        StoredMmr::<Sha256Hasher>::leaf_count(&inner.manifest_mmr).unwrap()
    }

    /// Snapshot of every manifest-MMR leaf in index order.
    pub fn mmr_leaves(&self) -> Vec<[u8; 32]> {
        let inner = self.inner.lock().unwrap();
        let count = StoredMmr::<Sha256Hasher>::leaf_count(&inner.manifest_mmr).unwrap();
        (0..count)
            .map(|i| {
                StoredMmr::<Sha256Hasher>::get_leaf(&inner.manifest_mmr, i)
                    .unwrap()
                    .expect("leaf below count is present")
            })
            .collect()
    }
}

impl L1DataProvider for TestAsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        // Fetch from regtest. We must handle two calling contexts:
        // 1. From within a tokio runtime (test thread) — use `block_in_place` to avoid "cannot
        //    start a runtime from within a runtime" panic.
        // 2. From the worker's dedicated OS thread (spawned by `spawn_critical`, no tokio context)
        //    — use the stored handle to drive the future on the original runtime where the HTTP
        //    client's connection pool lives.
        let block_hash = blockid.to_block_hash();
        let client = self.client.clone();
        let fetch = || async { client.get_block(&block_hash).await };
        let block = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::MissingL1Block(*blockid))?;

        Ok(block)
    }

    fn get_l1_block_header(&self, blockid: &L1BlockId) -> WorkerResult<Header> {
        // See `get_l1_block` for the two-context branching rationale.
        let block_hash = blockid.to_block_hash();
        let client = self.client.clone();
        let fetch = || async { client.get_block_header(&block_hash).await };
        let header = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::MissingL1Block(*blockid))?;

        Ok(header)
    }

    fn get_network(&self) -> WorkerResult<Network> {
        Ok(Network::Regtest)
    }

    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx> {
        let txid_inner: Txid = (*txid).into();

        // See `get_l1_block` for the two-context branching rationale.
        let client = self.client.clone();
        let fetch = || async move { client.get_raw_transaction_verbosity_zero(&txid_inner).await };
        let raw_tx_result = if Handle::try_current().is_ok() {
            block_in_place(|| self.tokio_handle.block_on(fetch()))
        } else {
            self.tokio_handle.block_on(fetch())
        }
        .map_err(|_| WorkerError::BitcoinTxNotFound(*txid))?;

        Ok(RawBitcoinTx::from(raw_tx_result.0))
    }
}

impl AnchorStateStore for TestAsmWorkerContext {
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        self.inner
            .lock()
            .unwrap()
            .asm_states
            .get(blockid)
            .cloned()
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn get_latest_asm_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AsmState)>> {
        Ok(self.inner.lock().unwrap().latest_asm_state.clone())
    }

    fn store_anchor_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.asm_states.insert(*blockid, state.clone());
        inner.latest_asm_state = Some((*blockid, state.clone()));
        Ok(())
    }
}

impl ManifestMmrStore for TestAsmWorkerContext {
    fn put_manifest(&self, manifest: AsmManifest) -> WorkerResult<()> {
        self.inner.lock().unwrap().manifests.push(manifest);
        Ok(())
    }

    fn put_manifest_hash(&self, height: u64, hash: AsmManifestHash) -> WorkerResult<()> {
        let inner = self.inner.lock().unwrap();
        StoredMmr::<Sha256Hasher>::put_leaf(&inner.manifest_mmr, height, *hash.as_ref())
            .map_err(|_| WorkerError::DbError)?;
        Ok(())
    }

    fn manifest_mmr_leaf_count(&self) -> WorkerResult<u64> {
        let inner = self.inner.lock().unwrap();
        StoredMmr::<Sha256Hasher>::leaf_count(&inner.manifest_mmr).map_err(|_| WorkerError::DbError)
    }

    fn generate_mmr_proof_at(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> WorkerResult<MerkleProofB32> {
        let inner = self.inner.lock().unwrap();
        let proof = StoredMmr::<Sha256Hasher>::generate_proof_at_size(
            &inner.manifest_mmr,
            index,
            at_leaf_count,
        )
        .map_err(|_| WorkerError::MmrProofFailed { index })?;
        Ok(MerkleProofB32::from_generic(&proof))
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<AsmManifestHash> {
        let inner = self.inner.lock().unwrap();
        StoredMmr::<Sha256Hasher>::get_leaf(&inner.manifest_mmr, index)
            .map_err(|_| WorkerError::DbError)?
            .map(AsmManifestHash::from)
            .ok_or(WorkerError::ManifestHashNotFound { index })
    }
}

impl AuxDataStore for TestAsmWorkerContext {
    fn store_aux_data(
        &self,
        _blockid: &L1BlockCommitment,
        _data: &strata_asm_common::AuxData,
    ) -> WorkerResult<()> {
        Ok(())
    }

    fn get_aux_data(
        &self,
        blockid: &L1BlockCommitment,
    ) -> WorkerResult<strata_asm_common::AuxData> {
        Err(WorkerError::MissingAuxData(*blockid))
    }
}

/// Helper to construct [`L1Anchor`] from a block hash using the client.
pub async fn get_l1_anchor(client: &Client, hash: &BlockHash) -> anyhow::Result<L1Anchor> {
    let header: Header = client.get_block_header(hash).await?;
    let height = client.get_block_height(hash).await?;

    // Construct L1BlockCommitment
    let blkid = header.block_hash().to_l1_block_id();
    let blk_commitment = L1BlockCommitment::new(height as u32, blkid);

    let network = client.network().await?;
    let params = Params::from(network);

    // `epoch_start_timestamp` is the timestamp of the *first* block of the current difficulty
    // epoch (Bitcoin retargets every `difficulty_adjustment_interval` blocks), not this block's
    // own timestamp. Regtest never retargets so it doesn't affect these tests, but model it
    // correctly regardless.
    let epoch_start_height = get_relative_difficulty_adjustment_height(0, height as u32, &params);
    let epoch_start_hash = client.get_block_hash(epoch_start_height as u64).await?;
    let epoch_start_timestamp = client.get_block_header(&epoch_start_hash).await?.time;

    // `next_target` only changes at a retarget boundary, which these tests never cross; off a
    // boundary the next target is just this block's target.
    let next_target = header.bits.to_consensus();

    Ok(L1Anchor {
        block: blk_commitment,
        next_target,
        epoch_start_timestamp,
        network,
    })
}
