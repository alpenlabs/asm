//! ASM worker context implementation for integration tests.
//!
//! Provides `TestAsmWorkerContext` which implements the `WorkerContext` trait,
//! allowing the ASM worker to fetch blocks and store state during tests.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bitcoin::{block::Header, Block, BlockHash, Network, Txid};
use bitcoind_async_client::{traits::Reader, Client};
use strata_asm_manifest_types::AsmManifest;
use strata_asm_worker::{AsmState, WorkerContext, WorkerError, WorkerResult};
use strata_btc_types::{BitcoinTxid, BlockHashExt, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_btc_verification::L1Anchor;
use strata_identifiers::{Buf32, Hash, L1BlockCommitment, L1BlockId};
use strata_merkle::{MerkleProofB32, Mmr, Mmr64B32, MmrState, Sha256Hasher};
use tokio::{runtime::Handle, task::block_in_place};

/// Shared mutable state for the test worker context.
///
/// Consolidating these fields lets us hold a single `Arc<Mutex<_>>` instead of
/// one per field, and keeps related invariants (mmr leaves + prefill count,
/// manifests in insertion order) close together.
#[derive(Debug, Default)]
pub struct TestWorkerStateInner {
    /// Block cache (optional - fetches from client if not cached)
    pub block_cache: HashMap<L1BlockId, Block>,
    /// ASM states indexed by L1 block commitment
    pub asm_states: HashMap<L1BlockCommitment, AsmState>,
    /// Latest ASM state
    pub latest_asm_state: Option<(L1BlockCommitment, AsmState)>,
    /// In-memory MMR leaves in insertion order.
    pub mmr_leaves: Vec<[u8; 32]>,
    /// Number of leading sentinel-prefill entries in `mmr_leaves`. Indices
    /// `0..mmr_prefill_count` are not real manifests.
    pub mmr_prefill_count: u64,
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

    /// Prefill the in-memory MMR with sentinel leaves up to `target_count`,
    /// mirroring the proven MMR's genesis prefill so DB-side leaf indices
    /// equal L1 block heights.
    pub fn prefill_mmr(&self, target_count: u64) {
        let sentinel = strata_asm_common::MMR_SENTINEL_DUMMY_LEAF;
        let mut inner = self.inner.lock().unwrap();
        for _ in inner.mmr_leaves.len() as u64..target_count {
            inner.mmr_leaves.push(sentinel);
        }
        inner.mmr_prefill_count = target_count.max(inner.mmr_prefill_count);
    }

    /// Fetch a block from regtest by hash, caching it for future use
    pub async fn fetch_and_cache_block(&self, block_hash: BlockHash) -> anyhow::Result<Block> {
        let block = self.client.get_block(&block_hash).await?;
        let block_id = block_hash.to_l1_block_id();
        self.inner
            .lock()
            .unwrap()
            .block_cache
            .insert(block_id, block.clone());
        Ok(block)
    }
}

impl WorkerContext for TestAsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        // Try cache first
        if let Some(block) = self.inner.lock().unwrap().block_cache.get(blockid).cloned() {
            return Ok(block);
        }

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

        // Cache for future use
        self.inner
            .lock()
            .unwrap()
            .block_cache
            .insert(*blockid, block.clone());

        Ok(block)
    }

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

    fn append_manifest_to_mmr(&self, manifest_hash: Hash) -> WorkerResult<u64> {
        let hash_bytes: [u8; 32] = *manifest_hash.as_ref();
        let mut inner = self.inner.lock().unwrap();
        let leaf_index = inner.mmr_leaves.len() as u64;
        inner.mmr_leaves.push(hash_bytes);
        Ok(leaf_index)
    }

    fn generate_mmr_proof_at(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> WorkerResult<strata_merkle::MerkleProofB32> {
        let inner = self.inner.lock().unwrap();
        if index >= at_leaf_count || at_leaf_count > inner.mmr_leaves.len() as u64 {
            return Err(WorkerError::MmrProofFailed { index });
        }

        // The MMR is height-indexed: positions `0..prefill_count` hold the
        // sentinel `MMR_PREFILL_LEAF`. Materialise the prefilled compact MMR
        // in O(log N) via `new_repeated`, then iterate only over real leaves
        // and track a single proof — the one for `index` — through subsequent
        // appends. We can't pre-populate proofs for prefill positions because
        // `new_repeated` doesn't expose per-leaf proofs; if `index` happens to
        // fall in the prefill range we walk the prefill manually instead.
        let prefill_count = inner.mmr_prefill_count.min(at_leaf_count);
        let (mut compact, walk_prefill_proofs) = if index < prefill_count {
            (Mmr64B32::new_empty(), true)
        } else {
            let compact = <Mmr64B32 as Mmr<Sha256Hasher>>::new_repeated(
                strata_asm_common::MMR_SENTINEL_DUMMY_LEAF,
                prefill_count,
            );
            (compact, false)
        };

        let mut proof_list: Vec<strata_merkle::MerkleProof<[u8; 32]>> = Vec::new();

        if walk_prefill_proofs {
            for i in 0..prefill_count {
                let leaf = strata_asm_common::MMR_SENTINEL_DUMMY_LEAF;
                let proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                    &mut compact,
                    leaf,
                    &mut proof_list,
                )
                .map_err(|_| WorkerError::MmrProofFailed { index })?;
                if i == index {
                    proof_list.push(proof);
                }
            }
        }

        for cur in prefill_count..at_leaf_count {
            let leaf = inner.mmr_leaves[cur as usize];
            let proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                &mut compact,
                leaf,
                &mut proof_list,
            )
            .map_err(|_| WorkerError::MmrProofFailed { index })?;
            if cur == index {
                proof_list.push(proof);
            }
        }

        // `proof_list` holds exactly one tracked proof — the one for `index` —
        // and `add_leaf_updating_proof_list` keeps it current through every
        // append performed after we inserted it.
        proof_list
            .first()
            .map(MerkleProofB32::from_generic)
            .ok_or(WorkerError::MmrProofFailed { index })
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<Option<Hash>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .mmr_leaves
            .get(index as usize)
            .copied()
            .map(Buf32::from))
    }

    fn store_l1_manifest(&self, manifest: AsmManifest) -> WorkerResult<()> {
        self.inner.lock().unwrap().manifests.push(manifest);
        Ok(())
    }

    fn store_aux_data(
        &self,
        _blockid: &L1BlockCommitment,
        _data: &strata_asm_common::AuxData,
    ) -> WorkerResult<()> {
        Ok(())
    }

    fn get_aux_data(
        &self,
        _blockid: &L1BlockCommitment,
    ) -> WorkerResult<Option<strata_asm_common::AuxData>> {
        Ok(None)
    }
}

/// Helper to construct [`L1Anchor`] from a block hash using the client.
pub async fn get_l1_anchor(client: &Client, hash: &BlockHash) -> anyhow::Result<L1Anchor> {
    let header: Header = client.get_block_header(hash).await?;
    let height = client.get_block_height(hash).await?;

    // Construct L1BlockCommitment
    let blkid = header.block_hash().to_l1_block_id();
    let blk_commitment = L1BlockCommitment::new(height as u32, blkid);

    // Create dummy/default values for other fields
    let next_target = header.bits.to_consensus();
    let epoch_start_timestamp = header.time;

    let network = client.network().await?;

    Ok(L1Anchor {
        block: blk_commitment,
        next_target,
        epoch_start_timestamp,
        network,
    })
}
