//! [`WorkerContext`] implementation for the ASM runner.
//!
//! # Moho extension
//!
//! When [`MohoStorage`] is configured, we piggyback on the ASM worker: every
//! anchor-state write in [`WorkerContext::store_anchor_state`] also
//! materializes and persists the derived [`MohoState`] for the same
//! [`L1BlockCommitment`]. The two databases advance together under a single
//! call — Moho does not run its own driver, does not subscribe to L1, and
//! does not manage its own chain view. Whatever block sequence the ASM worker
//! decides to apply (including any future reorg handling it gains) is the
//! sequence Moho sees, for free.

use std::sync::Arc;

use asm_storage::{AsmStateDb, ExportEntriesDb, MmrDb};
use bitcoin::{Block, BlockHash, Network};
use bitcoind_async_client::{Client, traits::Reader};
use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState};
use strata_asm_common::{AnchorState, AsmManifest, AuxData};
use strata_asm_logs::NewExportEntry;
use strata_asm_proof_db::SledMohoStateDb;
use strata_asm_proof_impl::moho_program::program::{
    AsmStfProgram, advance_export_state_with_logs, extract_next_predicate_from_logs,
};
use strata_asm_worker::{AsmState, WorkerContext, WorkerError, WorkerResult};
use strata_btc_types::{BitcoinTxid, BlockHashExt, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;
use tokio::runtime::Handle;

/// Dependencies the worker needs to materialize per-block [`MohoState`]
/// alongside each anchor state. `asm_predicate` is used only to seed the
/// genesis entry; every subsequent block is chain-forward from the parent.
pub(crate) struct MohoStorage {
    pub db: SledMohoStateDb,
    pub asm_predicate: PredicateKey,
}

/// ASM [`WorkerContext`] implementation.
///
/// Fetches L1 blocks from a Bitcoin node and persists state via local sled
/// storage. When [`MohoStorage`] is supplied, each anchor-state write also
/// materializes the derived [`MohoState`] for the same block.
pub(crate) struct AsmWorkerContext {
    runtime_handle: Handle,
    bitcoin_client: Arc<Client>,
    state_db: Arc<AsmStateDb>,
    mmr_db: Arc<MmrDb>,
    export_entries_db: Option<ExportEntriesDb>,
    moho_storage: Option<MohoStorage>,
}

impl AsmWorkerContext {
    pub(crate) fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        state_db: Arc<AsmStateDb>,
        mmr_db: Arc<MmrDb>,
        export_entries_db: Option<ExportEntriesDb>,
        moho_storage: Option<MohoStorage>,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            state_db,
            mmr_db,
            export_entries_db,
            moho_storage,
        }
    }

    /// Materialize and persist the derived [`MohoState`] for this anchor state.
    /// No-op when [`MohoStorage`] is not configured.
    ///
    /// Genesis is identified by the block commitment's height — it matches the
    /// `genesis_height` carried in the anchor state's history accumulator.
    /// For non-genesis blocks we read the parent's `MohoState` and chain
    /// forward.
    fn compute_and_store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        asm_state: &AsmState,
    ) -> WorkerResult<()> {
        let Some(moho) = &self.moho_storage else {
            return Ok(());
        };

        let genesis_height = asm_state
            .state()
            .chain_view
            .history_accumulator
            .genesis_height();

        let moho_state = if blockid.height() as u64 == genesis_height {
            construct_genesis_moho_state(moho.asm_predicate.clone(), asm_state.state())
        } else {
            let block = self.get_l1_block(blockid.blkid())?;
            let parent = L1BlockCommitment::new(
                blockid.height() - 1,
                block.header.prev_blockhash.to_l1_block_id(),
            );

            let prev_moho = moho
                .db
                .get(parent)
                .map_err(|_| WorkerError::DbError)?
                .ok_or(WorkerError::DbError)?; // TODO(STR-3124): use appropriate error types after fixing the piggybanking on ASM worker
            construct_next_moho_state(&prev_moho, asm_state)
        };

        moho.db
            .store(*blockid, moho_state)
            .map_err(|_| WorkerError::DbError)?;

        Ok(())
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
        self.state_db.get_latest().map_err(|_| WorkerError::DbError)
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        self.state_db
            .get(blockid)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn store_anchor_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        // Write order matters: moho first, then anchor. The worker tracks progress via the anchor
        // db (see get_latest_asm_state), so the anchor write is the effective commit point for
        // this block. If we crash between the two writes, progress has not advanced, so on
        // restart the worker reprocesses this block and overwrites the orphaned moho entry with
        // the same value. Reversing the order would risk advancing progress past a block whose
        // moho state was never persisted.
        self.compute_and_store_moho_state(blockid, state)?;

        self.state_db
            .put(blockid, state)
            .map_err(|_| WorkerError::DbError)?;

        // Index each `NewExportEntry` alongside the MohoState's compact MMR so
        // the RPC can regenerate inclusion proofs later.
        if let Some(ref export_entries_db) = self.export_entries_db {
            for log in state.logs() {
                if let Ok(export) = log.try_into_log::<NewExportEntry>() {
                    export_entries_db
                        .append(
                            export.container_id(),
                            blockid.height(),
                            *export.entry_data(),
                        )
                        .map_err(|_| WorkerError::DbError)?;
                }
            }
        }

        Ok(())
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

    fn append_manifest_to_mmr(&self, manifest_hash: Buf32) -> WorkerResult<u64> {
        self.mmr_db
            .append_leaf(manifest_hash)
            .map_err(|_| WorkerError::DbError)
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

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<Option<Buf32>> {
        self.mmr_db
            .get_leaf(index)
            .map_err(|_| WorkerError::DbError)
    }

    fn store_aux_data(&self, blockid: &L1BlockCommitment, data: &AuxData) -> WorkerResult<()> {
        self.state_db
            .put_aux_data(blockid, data)
            .map_err(|_| WorkerError::DbError)
    }

    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> WorkerResult<Option<AuxData>> {
        self.state_db
            .get_aux_data(blockid)
            .map_err(|_| WorkerError::DbError)
    }

    fn has_l1_manifest(&self, _blockid: &L1BlockId) -> WorkerResult<bool> {
        Ok(true)
    }
}

/// Seed the genesis [`MohoState`]: no prior state to chain forward from, so we
/// use the configured `asm_predicate` and an empty export state.
fn construct_genesis_moho_state(
    asm_predicate: PredicateKey,
    genesis_anchor_state: &AnchorState,
) -> MohoState {
    let inner = AsmStfProgram::compute_state_commitment(genesis_anchor_state);
    let export_state = ExportState::new(vec![]).expect("empty export state is always valid");
    MohoState::new(inner, asm_predicate, export_state)
}

/// Chain-forward the [`MohoState`]: let STF logs drive predicate and export
/// state updates, and recompute the inner commitment from the new anchor state.
fn construct_next_moho_state(prev_moho: &MohoState, state: &AsmState) -> MohoState {
    let next_predicate = extract_next_predicate_from_logs(state.logs())
        .unwrap_or_else(|| prev_moho.next_predicate().clone());
    let next_export_state =
        advance_export_state_with_logs(prev_moho.export_state().clone(), state.logs());
    let inner = AsmStfProgram::compute_state_commitment(state.state());
    MohoState::new(inner, next_predicate, next_export_state)
}
