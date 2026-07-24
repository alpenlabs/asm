//! Worker-context trait implementations for the ASM runner.
//!
//! Implements the five [`WorkerContext`](strata_asm_worker::WorkerContext)
//! concern traits ([`L1DataProvider`], [`AnchorStateStore`],
//! [`ManifestMmrStore`], [`AuxDataStore`], [`SpecActivationStore`]) for
//! [`AsmWorkerContext`].

use std::sync::Arc;

use anyhow::{Context, anyhow};
use asm_storage::{
    SledAsmAuxDataDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb, SledSpecActivationDb,
};
use bitcoin::{Block, BlockHash, Network, block::Header};
use bitcoind_async_client::{Client, traits::Reader};
use strata_asm_common::{AnchorState, AsmManifest, AsmManifestHash, AuxData};
use strata_asm_worker::{
    AnchorStateStore, AuxDataStore, L1DataProvider, ManifestMmrStore, SpecActivationRecord,
    SpecActivationStore, WorkerError, WorkerResult,
};
use strata_btc_types::{BitcoinTxid, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{L1BlockCommitment, L1BlockId, L1Height};
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
    spec_activation_db: Arc<SledSpecActivationDb>,
}

impl AsmWorkerContext {
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per storage concern"
    )]
    pub(crate) fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        retry: &RetryConfig,
        state_db: Arc<SledAsmStateDb>,
        aux_db: Arc<SledAsmAuxDataDb>,
        manifest_db: Arc<SledAsmManifestDb>,
        mmr_db: Arc<SledAsmManifestMmrDb>,
        spec_activation_db: Arc<SledSpecActivationDb>,
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
            spec_activation_db,
        }
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
            .with_context(|| format!("get_block({block_hash})"))
            .map_err(WorkerError::BtcRpc)
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
            .with_context(|| format!("get_block_header({block_hash})"))
            .map_err(WorkerError::BtcRpc)
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
            .with_context(|| format!("get_block_hash({height})"))
            .map_err(WorkerError::BtcRpc)?;
        self.runtime_handle
            .block_on(retry_with_backoff_async(
                "btc_get_block_header",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block_header(&block_hash).await },
            ))
            .with_context(|| format!("get_block_header({block_hash})"))
            .map_err(WorkerError::BtcRpc)
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
            .with_context(|| format!("get_block_height({block_hash})"))
            .map_err(WorkerError::BtcRpc)
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
            .context("network")
            .map_err(WorkerError::BtcRpc)
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
            .with_context(|| format!("get_raw_transaction({bitcoin_txid})"))
            .map_err(WorkerError::BtcRpc)
    }
}

impl AnchorStateStore for AsmWorkerContext {
    // The state store persists the `AnchorState` on its own; the STF logs live
    // in the manifest store and every consumer that needs them (the Moho
    // worker's `get_anchor_logs`, the checkpoint/bridge test harness) reads them
    // from there directly, keyed by block.
    fn get_latest_anchor_state(&self) -> WorkerResult<Option<AnchorState>> {
        self.state_db.get_latest().map_err(WorkerError::DbError)
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AnchorState> {
        self.state_db
            .get(blockid)
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn store_anchor_state(&self, state: &AnchorState) -> WorkerResult<()> {
        self.state_db.put(state).map_err(WorkerError::DbError)?;

        Ok(())
    }
}

impl ManifestMmrStore for AsmWorkerContext {
    fn put_manifest(&self, manifest: AsmManifest) -> WorkerResult<()> {
        self.manifest_db
            .put(&manifest)
            .map_err(WorkerError::DbError)
    }

    fn put_manifest_hash(&self, height: u64, hash: AsmManifestHash) -> WorkerResult<()> {
        self.mmr_db
            .put_leaf(height, hash)
            .map_err(WorkerError::DbError)
    }

    fn manifest_mmr_leaf_count(&self) -> WorkerResult<u64> {
        self.mmr_db.leaf_count().map_err(WorkerError::DbError)
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
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::ManifestHashNotFound { index })
    }
}

impl SpecActivationStore for AsmWorkerContext {
    fn record_spec_activation(&self, activation: SpecActivationRecord) -> WorkerResult<()> {
        self.spec_activation_db
            .put(
                activation.enacting_height,
                activation.version.into(),
                &activation.new_predicate,
            )
            .map_err(WorkerError::DbError)
    }

    fn list_spec_activations(&self) -> WorkerResult<Vec<SpecActivationRecord>> {
        self.spec_activation_db
            .list()
            .map_err(WorkerError::DbError)?
            .into_iter()
            .map(|(enacting_height, version, new_predicate)| {
                SpecActivationRecord::from_raw(enacting_height, version, new_predicate).map_err(
                    |id| {
                        WorkerError::DbError(anyhow!(
                            "unknown spec version {id} in spec activation store"
                        ))
                    },
                )
            })
            .collect()
    }

    fn prune_spec_activations_after(&self, after_height: L1Height) -> WorkerResult<()> {
        self.spec_activation_db
            .prune_after(after_height)
            .map_err(WorkerError::DbError)
    }
}

impl AuxDataStore for AsmWorkerContext {
    fn store_aux_data(&self, blockid: &L1BlockCommitment, data: &AuxData) -> WorkerResult<()> {
        self.aux_db.put(blockid, data).map_err(WorkerError::DbError)
    }

    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> WorkerResult<AuxData> {
        self.aux_db
            .get(blockid)
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::MissingAuxData(*blockid))
    }
}
