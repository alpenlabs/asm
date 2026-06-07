//! Worker-context trait implementations for the ASM runner.
//!
//! Implements the four [`WorkerContext`](strata_asm_worker::WorkerContext)
//! concern traits ([`L1DataProvider`], [`AnchorStateStore`],
//! [`ManifestMmrStore`], [`AuxDataStore`]) for [`AsmWorkerContext`].
//!
//! # Moho extension
//!
//! When [`MohoStorage`] is configured, we piggyback on the ASM worker: every
//! anchor-state write in [`AnchorStateStore::store_anchor_state`] also
//! materializes and persists the derived [`MohoState`] for the same
//! [`L1BlockCommitment`]. The two databases advance together under a single
//! call — Moho does not run its own driver, does not subscribe to L1, and
//! does not manage its own chain view. Whatever block sequence the ASM worker
//! decides to apply (including any future reorg handling it gains) is the
//! sequence Moho sees, for free.

use std::sync::Arc;

use asm_storage::{
    ExportEntriesDb, SledAsmAuxDataDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb,
};
use bitcoin::{Block, BlockHash, Network, block::Header};
use bitcoind_async_client::{Client, error::ClientError, traits::Reader};
use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState};
use strata_asm_common::{AnchorState, AsmManifest, AsmManifestHash, AuxData};
use strata_asm_logs::NewExportEntry;
use strata_asm_proof_db::SledMohoStateDb;
use strata_asm_proof_impl::moho_program::program::{
    AsmStfProgram, advance_export_state_with_logs, extract_next_predicate_from_logs,
};
use strata_asm_worker::{
    AnchorStateStore, AsmState, AuxDataStore, L1DataProvider, ManifestMmrStore, WorkerError,
    WorkerResult,
};
use strata_btc_types::{BitcoinTxid, BlockHashExt, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;
use tokio::runtime::Handle;

use crate::retry::{ExponentialBackoff, RetryConfig, retry_with_backoff_async};

/// Dependencies the worker needs to materialize per-block [`MohoState`]
/// alongside each anchor state. `asm_predicate` is used only to seed the
/// genesis entry; every subsequent block is chain-forward from the parent.
pub(crate) struct MohoStorage {
    pub db: SledMohoStateDb,
    pub asm_predicate: PredicateKey,
}

/// ASM [`WorkerContext`](strata_asm_worker::WorkerContext) implementation.
///
/// Fetches L1 blocks from a Bitcoin node and persists state via local sled
/// storage. When [`MohoStorage`] is supplied, each anchor-state write also
/// materializes the derived [`MohoState`] for the same block.
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
    export_entries_db: Option<ExportEntriesDb>,
    moho_storage: Option<MohoStorage>,
    /// L1 height of the chain genesis (anchor) block.
    genesis_height: u64,
}

impl AsmWorkerContext {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor wires every dependency the worker holds; one call site"
    )]
    pub(crate) fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        retry: &RetryConfig,
        state_db: Arc<SledAsmStateDb>,
        aux_db: Arc<SledAsmAuxDataDb>,
        manifest_db: Arc<SledAsmManifestDb>,
        mmr_db: Arc<SledAsmManifestMmrDb>,
        export_entries_db: Option<ExportEntriesDb>,
        moho_storage: Option<MohoStorage>,
        genesis_height: u64,
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
            export_entries_db,
            moho_storage,
            genesis_height,
        }
    }

    /// Materialize and persist the derived [`MohoState`] for this anchor state.
    /// No-op when [`MohoStorage`] is not configured.
    ///
    /// Genesis is identified by the block commitment's height matching the
    /// configured `genesis_height`. For non-genesis blocks we read the parent's
    /// `MohoState` and chain forward.
    fn compute_and_store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        asm_state: &AsmState,
    ) -> WorkerResult<()> {
        let Some(moho) = &self.moho_storage else {
            return Ok(());
        };

        let genesis_height = self.genesis_height;

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
    // umbrella also carries logs, which live in the manifest store. The logs are
    // not needed to drive transitions (the worker reads only `AsmState::state()`),
    // so reads reconstruct an `AsmState` with empty logs — matching how genesis
    // is seeded.
    fn get_latest_asm_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AsmState)>> {
        Ok(self
            .state_db
            .get_latest()
            .map_err(|_| WorkerError::DbError)?
            .map(|anchor| {
                let blockid = anchor.chain_view.pow_state.last_verified_block;
                (blockid, AsmState::new(anchor, vec![]))
            }))
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        let anchor = self
            .state_db
            .get(blockid)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))?;
        Ok(AsmState::new(anchor, vec![]))
    }

    fn store_anchor_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        // Write order matters: moho and export_entries first, then anchor. The worker tracks
        // progress via the anchor db (see get_latest_asm_state), so the anchor write is the
        // effective commit point for this block. If we crash before it, progress has not
        // advanced, so on restart the worker reprocesses this block and overwrites the
        // orphaned entries with the same values. Reversing the order would risk advancing
        // progress past a block whose moho or export_entries state was never persisted.
        self.compute_and_store_moho_state(blockid, state)?;

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
