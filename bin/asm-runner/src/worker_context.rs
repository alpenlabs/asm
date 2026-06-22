//! Worker-context trait implementations for the ASM runner.
//!
//! Implements the four [`WorkerContext`](strata_asm_worker::WorkerContext)
//! concern traits ([`L1DataProvider`], [`AnchorStateStore`],
//! [`ManifestMmrStore`], [`AuxDataStore`]) for [`AsmWorkerContext`].

use std::sync::Arc;

use asm_storage::{SledAsmAuxDataDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb};
use bitcoin::{Block, BlockHash, Network, block::Header};
use bitcoind_async_client::{Client, error::ClientError, traits::Reader};
use strata_asm_common::{AsmLogEntry, AsmManifest, AsmManifestHash, AuxData};
use strata_asm_worker::{
    AnchorStateStore, AsmState, AuxDataStore, L1DataProvider, ManifestMmrStore, WorkerError,
    WorkerResult,
};
use strata_btc_types::{BitcoinTxid, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_merkle::MerkleProofB32;
use tokio::runtime::Handle;

use crate::retry::{ExponentialBackoff, RetryConfig, retry_with_backoff_async};

/// ASM [`WorkerContext`](strata_asm_worker::WorkerContext) implementation.
///
/// Fetches L1 blocks from a Bitcoin node and persists state via local sled
/// storage. Moho state and the export-entries index are derived separately by
/// the Moho worker; see [`moho_context`](crate::moho_context).
pub(crate) struct AsmWorkerContext {
    runtime_handle: Handle,
    bitcoin_client: Arc<Client>,
    /// Backoff schedule for Bitcoin RPC calls.
    rpc_backoff: ExponentialBackoff,
    /// Maximum retry attempts per Bitcoin RPC call.
    rpc_max_retries: u16,
    state_db: Arc<SledAsmStateDb>,
    aux_db: Arc<SledAsmAuxDataDb>,
    manifest_db: Arc<SledAsmManifestDb>,
    mmr_db: Arc<SledAsmManifestMmrDb>,
}

impl AsmWorkerContext {
    pub(crate) fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        retry: &RetryConfig,
        state_db: Arc<SledAsmStateDb>,
        aux_db: Arc<SledAsmAuxDataDb>,
        manifest_db: Arc<SledAsmManifestDb>,
        mmr_db: Arc<SledAsmManifestMmrDb>,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            rpc_backoff: retry.backoff(),
            rpc_max_retries: retry.max_retries,
            state_db,
            aux_db,
            manifest_db,
            mmr_db,
        }
    }

    /// Loads the STF logs for `blockid` from the manifest store.
    ///
    /// The anchor state DB persists only the `AnchorState`, so the logs the STF
    /// emitted are recovered from the block's manifest. Returns an empty vec
    /// when no manifest is stored — e.g. the genesis anchor, seeded without
    /// running the STF.
    fn manifest_logs(&self, blockid: &L1BlockCommitment) -> WorkerResult<Vec<AsmLogEntry>> {
        Ok(self
            .manifest_db
            .get(blockid)
            .map_err(|_| WorkerError::DbError)?
            .map(|manifest| manifest.logs().to_vec())
            .unwrap_or_default())
    }
}

impl L1DataProvider for AsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        let block_hash: BlockHash = blockid.to_block_hash();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_block",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block(&block_hash).await },
            ))
            .map_err(|e: ClientError| WorkerError::BtcRpc(format!("get_block({block_hash}): {e}")))
    }

    fn get_l1_block_header(&self, blockid: &L1BlockId) -> WorkerResult<Header> {
        let block_hash: BlockHash = blockid.to_block_hash();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_block_header",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block_header(&block_hash).await },
            ))
            .map_err(|e: ClientError| {
                WorkerError::BtcRpc(format!("get_block_header({block_hash}): {e}"))
            })
    }

    fn get_l1_block_header_at_height(&self, height: u64) -> WorkerResult<Header> {
        let client = &self.bitcoin_client;
        let block_hash = self
            .runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_block_hash",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block_hash(height).await },
            ))
            .map_err(|e: ClientError| {
                WorkerError::BtcRpc(format!("get_block_hash({height}): {e}"))
            })?;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_block_header",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block_header(&block_hash).await },
            ))
            .map_err(|e: ClientError| {
                WorkerError::BtcRpc(format!("get_block_header({block_hash}): {e}"))
            })
    }

    fn get_l1_block_height(&self, blockid: &L1BlockId) -> WorkerResult<u64> {
        let block_hash: BlockHash = blockid.to_block_hash();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_block_height",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block_height(&block_hash).await },
            ))
            .map_err(|e: ClientError| {
                WorkerError::BtcRpc(format!("get_block_height({block_hash}): {e}"))
            })
    }

    fn get_network(&self) -> WorkerResult<Network> {
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_network",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.network().await },
            ))
            .map_err(|e: ClientError| WorkerError::BtcRpc(format!("network: {e}")))
    }

    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx> {
        let bitcoin_txid = txid.inner();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_raw_transaction",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async {
                    client
                        .get_raw_transaction_verbosity_zero(&bitcoin_txid)
                        .await
                },
            ))
            .map(|resp| RawBitcoinTx::from(resp.0))
            .map_err(|e: ClientError| {
                WorkerError::BtcRpc(format!("get_raw_transaction({bitcoin_txid}): {e}"))
            })
    }
}

impl AnchorStateStore for AsmWorkerContext {
    // The state store persists only the `AnchorState`; the worker's `AsmState`
    // umbrella also carries the STF logs, which live in the manifest store.
    // Reads rejoin the two so the reconstructed `AsmState` matches what the STF
    // produced — anything that derives from the logs (the MohoState, the
    // export-entry index) then stays correct even when it runs over a reloaded
    // state rather than fresh STF output. Returning empty logs here once let a
    // re-committed anchor silently drop a block's export entries and predicate
    // update, desyncing its persisted MohoState from the proven one.
    fn get_latest_asm_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AsmState)>> {
        let Some(anchor) = self
            .state_db
            .get_latest()
            .map_err(|_| WorkerError::DbError)?
        else {
            return Ok(None);
        };
        let blockid = anchor.chain_view.pow_state.last_verified_block;
        let logs = self.manifest_logs(&blockid)?;
        Ok(Some((blockid, AsmState::new(anchor, logs))))
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        let anchor = self
            .state_db
            .get(blockid)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))?;
        let logs = self.manifest_logs(blockid)?;
        Ok(AsmState::new(anchor, logs))
    }

    fn store_anchor_state(
        &self,
        _blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        self.state_db
            .put(state.state())
            .map_err(|_| WorkerError::DbError)?;

        Ok(())
    }
}

impl ManifestMmrStore for AsmWorkerContext {
    fn put_manifest(&self, manifest: AsmManifest) -> WorkerResult<()> {
        self.manifest_db
            .put(&manifest)
            .map_err(|_| WorkerError::DbError)
    }

    fn put_manifest_hash(&self, height: u64, hash: AsmManifestHash) -> WorkerResult<()> {
        self.mmr_db
            .put_leaf(height, hash)
            .map_err(|_| WorkerError::DbError)
    }

    fn manifest_mmr_leaf_count(&self) -> WorkerResult<u64> {
        self.mmr_db.leaf_count().map_err(|_| WorkerError::DbError)
    }

    fn generate_mmr_proof_at(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> WorkerResult<MerkleProofB32> {
        self.mmr_db
            .generate_proof(index, at_leaf_count)
            .map_err(|_| WorkerError::MmrProofFailed { index })
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<AsmManifestHash> {
        self.mmr_db
            .get_leaf(index)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::ManifestHashNotFound { index })
    }
}

impl AuxDataStore for AsmWorkerContext {
    fn store_aux_data(&self, blockid: &L1BlockCommitment, data: &AuxData) -> WorkerResult<()> {
        self.aux_db
            .put(blockid, data)
            .map_err(|_| WorkerError::DbError)
    }

    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> WorkerResult<AuxData> {
        self.aux_db
            .get(blockid)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAuxData(*blockid))
    }
}
