//! WorkerContext implementation for ASM worker.
//!
//! This is the glue between the worker (which uses `strata_asm_worker::AsmState`)
//! and the storage layer (which uses `strata_state::asm_state::AsmState`).
//! The two types are structurally identical — we convert between them at the
//! persistence boundary.

use std::sync::Arc;

use bitcoin::{Block, BlockHash, Network};
use bitcoind_async_client::{Client, traits::Reader};
use strata_asm_common::{AsmManifest, AuxData};
use strata_asm_worker::{AsmState, WorkerContext, WorkerError, WorkerResult};
use strata_btc_types::{BitcoinTxid, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{Hash, L1BlockCommitment, L1BlockId};
use strata_state::asm_state::AsmState as StorageAsmState;
use strata_storage::{AsmStateManager, MmrIndexHandle};
use tokio::runtime::Handle;

/// Convert storage-layer AsmState to worker AsmState.
fn from_storage(s: StorageAsmState) -> AsmState {
    AsmState::new(s.state().clone(), s.logs().clone())
}

/// Convert worker AsmState to storage-layer AsmState.
fn to_storage(s: &AsmState) -> StorageAsmState {
    StorageAsmState::new(s.state().clone(), s.logs().clone())
}

/// ASM [`WorkerContext`] implementation.
///
/// Fetches L1 blocks from a Bitcoin node and persists state via SledDB.
pub(crate) struct AsmWorkerContext {
    runtime_handle: Handle,
    bitcoin_client: Arc<Client>,
    asm_manager: Arc<AsmStateManager>,
    mmr_handle: MmrIndexHandle,
}

impl AsmWorkerContext {
    pub(crate) const fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        asm_manager: Arc<AsmStateManager>,
        mmr_handle: MmrIndexHandle,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            asm_manager,
            mmr_handle,
        }
    }
}

impl WorkerContext for AsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        let block_hash: BlockHash = blockid.to_block_hash();
        self.runtime_handle
            .block_on(self.bitcoin_client.get_block(&block_hash))
            .map_err(|_| WorkerError::MissingL1Block(*blockid))
    }

    fn get_latest_asm_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AsmState)>> {
        self.asm_manager
            .fetch_most_recent_state()
            .map(|opt| opt.map(|(id, s)| (id, from_storage(s))))
            .map_err(|_| WorkerError::DbError)
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        self.asm_manager
            .get_state(*blockid)
            .map(|opt| opt.map(from_storage))
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn store_anchor_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        self.asm_manager
            .put_state(*blockid, to_storage(state))
            .map_err(|_| WorkerError::DbError)
    }

    fn store_l1_manifest(&self, _manifest: AsmManifest) -> WorkerResult<()> {
        Ok(())
    }

    fn get_network(&self) -> WorkerResult<Network> {
        self.runtime_handle
            .block_on(self.bitcoin_client.network())
            .map_err(|_| WorkerError::BtcClient)
    }

    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx> {
        let bitcoin_txid = txid.inner();
        self.runtime_handle
            .block_on(
                self.bitcoin_client
                    .get_raw_transaction_verbosity_zero(&bitcoin_txid),
            )
            .map(|resp| RawBitcoinTx::from(resp.0))
            .map_err(|_| WorkerError::BitcoinTxNotFound(*txid))
    }

    fn append_manifest_to_mmr(&self, manifest_hash: Hash) -> WorkerResult<u64> {
        self.mmr_handle
            .append_leaf_blocking(manifest_hash)
            .map_err(|_| WorkerError::DbError)
    }

    fn generate_mmr_proof_at(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> WorkerResult<strata_merkle::MerkleProofB32> {
        self.mmr_handle
            .generate_proof_at(index, at_leaf_count)
            .map_err(|_| WorkerError::MmrProofFailed { index })
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<Option<Hash>> {
        self.mmr_handle
            .get_leaf_blocking(index)
            .map_err(|_| WorkerError::DbError)
    }

    fn store_aux_data(&self, blockid: &L1BlockCommitment, data: &AuxData) -> WorkerResult<()> {
        self.asm_manager
            .put_aux_data(*blockid, data.clone())
            .map_err(|_| WorkerError::DbError)
    }

    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> WorkerResult<Option<AuxData>> {
        self.asm_manager
            .get_aux_data(*blockid)
            .map_err(|_| WorkerError::DbError)
    }

    fn has_l1_manifest(&self, _blockid: &L1BlockId) -> WorkerResult<bool> {
        Ok(true)
    }
}
