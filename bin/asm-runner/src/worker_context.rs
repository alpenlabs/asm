//! Worker-context trait implementations for the ASM runner.
//!
//! Implements the four [`WorkerContext`](strata_asm_worker::WorkerContext)
//! concern traits ([`L1DataProvider`], [`AnchorStateStore`],
//! [`ManifestMmrStore`], [`AuxDataStore`]) for [`AsmWorkerContext`].

use std::sync::Arc;

use anyhow::Context;
use asm_storage::{
    SledAsmAuxDataDb, SledAsmHandoverDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb,
};
use bitcoin::{Block, BlockHash, Network, block::Header};
use strata_asm_common::{AnchorState, AsmManifest, AsmManifestHash, AuxData};
use strata_asm_worker::{
    AnchorStateStore, AsmHandoverStore, AuxDataStore, L1DataProvider, ManifestMmrStore,
    WorkerError, WorkerResult,
};
use strata_btc_types::{BitcoinTxid, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{L1BlockCommitment, L1BlockId, L1Height};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;
use tokio::runtime::Handle;

use crate::bitcoin_client::RetryingBitcoinClient;

/// ASM [`WorkerContext`](strata_asm_worker::WorkerContext) implementation.
///
/// Fetches L1 blocks from a Bitcoin node and persists state via local sled
/// storage. Moho state and the export-entries index are derived separately by
/// the Moho worker; see [`moho_context`](crate::moho_context).
pub(crate) struct AsmWorkerContext {
    runtime_handle: Handle,
    bitcoin_client: Arc<RetryingBitcoinClient>,
    state_db: Arc<SledAsmStateDb>,
    aux_db: Arc<SledAsmAuxDataDb>,
    handover_db: Arc<SledAsmHandoverDb>,
    manifest_db: Arc<SledAsmManifestDb>,
    mmr_db: Arc<SledAsmManifestMmrDb>,
}

impl AsmWorkerContext {
    pub(crate) fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<RetryingBitcoinClient>,
        state_db: Arc<SledAsmStateDb>,
        aux_db: Arc<SledAsmAuxDataDb>,
        handover_db: Arc<SledAsmHandoverDb>,
        manifest_db: Arc<SledAsmManifestDb>,
        mmr_db: Arc<SledAsmManifestMmrDb>,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            state_db,
            aux_db,
            handover_db,
            manifest_db,
            mmr_db,
        }
    }
}

impl L1DataProvider for AsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        let block_hash: BlockHash = blockid.to_block_hash();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(client.get_block(&block_hash))
            .with_context(|| format!("get_block({block_hash})"))
            .map_err(WorkerError::BtcRpc)
    }

    fn get_l1_block_header(&self, blockid: &L1BlockId) -> WorkerResult<Header> {
        let block_hash: BlockHash = blockid.to_block_hash();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(client.get_block_header(&block_hash))
            .with_context(|| format!("get_block_header({block_hash})"))
            .map_err(WorkerError::BtcRpc)
    }

    fn get_l1_block_header_at_height(&self, height: L1Height) -> WorkerResult<Header> {
        let client = &self.bitcoin_client;
        let height = u64::from(height);
        let block_hash = self
            .runtime_handle
            .block_on(client.get_block_hash(height))
            .with_context(|| format!("get_block_hash({height})"))
            .map_err(WorkerError::BtcRpc)?;
        self.runtime_handle
            .block_on(client.get_block_header(&block_hash))
            .with_context(|| format!("get_block_header({block_hash})"))
            .map_err(WorkerError::BtcRpc)
    }

    fn get_l1_block_height(&self, blockid: &L1BlockId) -> WorkerResult<L1Height> {
        let block_hash: BlockHash = blockid.to_block_hash();
        let client = &self.bitcoin_client;
        let height = self
            .runtime_handle
            .block_on(client.get_block_height(&block_hash))
            .with_context(|| format!("get_block_height({block_hash})"))
            .map_err(WorkerError::BtcRpc)?;
        L1Height::try_from(height).map_err(|_| WorkerError::HeightOutOfRange { height })
    }

    fn get_network(&self) -> WorkerResult<Network> {
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(client.network())
            .context("network")
            .map_err(WorkerError::BtcRpc)
    }

    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx> {
        let bitcoin_txid = txid.inner();
        let client = &self.bitcoin_client;
        self.runtime_handle
            .block_on(client.get_raw_transaction_verbosity_zero(&bitcoin_txid))
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
    fn get_latest_anchor_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AnchorState)>> {
        self.state_db.get_latest().map_err(WorkerError::DbError)
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AnchorState> {
        self.state_db
            .get(blockid)
            .map_err(WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn store_anchor_state(&self, state: &AnchorState) -> WorkerResult<()> {
        self.state_db.commit(state).map_err(WorkerError::DbError)?;

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

impl AsmHandoverStore for AsmWorkerContext {
    fn store_next_predicate(
        &self,
        block: &L1BlockCommitment,
        predicate: &PredicateKey,
    ) -> WorkerResult<()> {
        self.handover_db
            .put(block, predicate)
            .map_err(WorkerError::DbError)
    }

    fn get_next_predicate(&self, block: &L1BlockCommitment) -> WorkerResult<Option<PredicateKey>> {
        self.handover_db.get(block).map_err(WorkerError::DbError)
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
