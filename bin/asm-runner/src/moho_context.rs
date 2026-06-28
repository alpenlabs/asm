//! Moho worker-context implementation for the ASM runner.
//!
//! [`MohoWorkerContextImpl`] backs the three concern traits the Moho worker
//! interfaces through ([`AsmStateProvider`], [`L1ProviderContext`],
//! [`MohoStateStore`]). It reads the anchor states the ASM worker committed (via
//! [`SledAsmStateDb`]) and the per-block logs from their manifests (via
//! [`SledAsmManifestDb`]), resolves L1 parents from the Bitcoin node, and
//! persists derived Moho states via [`SledMohoStateDb`].
//!
//! Unlike the ASM worker — which runs on its own thread and can block on Bitcoin
//! RPC directly — the Moho worker runs as an async service. The
//! [`MohoWorkerContext`](strata_asm_moho_worker::MohoWorkerContext) traits are
//! synchronous, so parent resolution bridges to the async client via
//! [`block_in_place`](task::block_in_place); see
//! [`MohoWorkerContextImpl::get_parent_block`].

use std::sync::Arc;

use asm_storage::{SledAsmManifestDb, SledAsmStateDb};
use bitcoin::BlockHash;
use bitcoind_async_client::{Client, error::ClientError, traits::Reader};
use moho_types::MohoState;
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_moho_storage::{SledExportEntriesDb, SledMohoStateDb};
use strata_asm_moho_worker::{
    AsmStateProvider, ExportEntryStore, L1ProviderContext, MohoStateStore, MohoWorkerError,
    MohoWorkerResult,
};
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_identifiers::L1BlockCommitment;
use tokio::{runtime::Handle, task};

use crate::retry::{ExponentialBackoff, RetryConfig, retry_with_backoff_async};

/// Storage and L1 access the Moho worker derives per-block Moho states from.
pub(crate) struct MohoWorkerContextImpl {
    runtime_handle: Handle,
    bitcoin_client: Arc<Client>,
    /// Backoff schedule for Bitcoin RPC calls.
    rpc_backoff: ExponentialBackoff,
    /// Maximum retry attempts per Bitcoin RPC call.
    rpc_max_retries: u16,
    /// ASM anchor states the Moho state is derived from, committed by the ASM
    /// worker.
    state_db: Arc<SledAsmStateDb>,
    /// Per-block ASM manifests, the source of the logs the Moho state folds in.
    /// Committed by the ASM worker alongside each anchor state.
    manifest_db: Arc<SledAsmManifestDb>,
    /// Persistence for the derived per-block Moho states.
    moho_state_db: SledMohoStateDb,
    /// Persistence for the per-container export-entry leaves the Moho state's
    /// `ExportState` MMR commits to.
    export_entries_db: SledExportEntriesDb,
}

impl MohoWorkerContextImpl {
    pub(crate) fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        retry: &RetryConfig,
        state_db: Arc<SledAsmStateDb>,
        manifest_db: Arc<SledAsmManifestDb>,
        moho_state_db: SledMohoStateDb,
        export_entries_db: SledExportEntriesDb,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            rpc_backoff: retry.backoff(),
            rpc_max_retries: retry.max_retries,
            state_db,
            manifest_db,
            moho_state_db,
            export_entries_db,
        }
    }
}

impl AsmStateProvider for MohoWorkerContextImpl {
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<AnchorState> {
        self.state_db
            .get(blockid)
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))?
            .ok_or(MohoWorkerError::MissingAsmState(*blockid))
    }

    fn get_anchor_logs(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<Vec<AsmLogEntry>> {
        // The ASM worker commits each block's manifest before its anchor state,
        // so whenever the anchor exists the manifest does too; a missing manifest
        // means the block's ASM commit is absent. An empty log list is a present
        // manifest with no logs.
        self.manifest_db
            .get(blockid)
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))?
            .map(|manifest| manifest.logs().to_vec())
            .ok_or(MohoWorkerError::MissingAsmState(*blockid))
    }

    fn get_latest_asm_block(&self) -> MohoWorkerResult<Option<L1BlockCommitment>> {
        Ok(self
            .state_db
            .get_latest()
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))?
            .map(|anchor| anchor.chain_view.pow_state.last_verified_block))
    }
}

impl L1ProviderContext for MohoWorkerContextImpl {
    fn get_parent_block(&self, block: &L1BlockCommitment) -> MohoWorkerResult<L1BlockCommitment> {
        let block_hash: BlockHash = block.blkid().to_block_hash();
        let client = &self.bitcoin_client;

        // The context traits are synchronous but the Bitcoin RPC is async, and
        // the Moho worker runs as an async service — a nested `Handle::block_on`
        // would panic. `block_in_place` releases the current worker thread for
        // the blocking call so the runtime keeps making progress; it requires
        // the multi-threaded runtime the runner builds.
        let header = task::block_in_place(|| {
            self.runtime_handle.block_on(retry_with_backoff_async(
                "btc_get_block_header",
                self.rpc_max_retries,
                &self.rpc_backoff,
                || async { client.get_block_header(&block_hash).await },
            ))
        })
        .map_err(|_: ClientError| MohoWorkerError::MissingParentBlock(*block))?;

        let parent_id = header.prev_blockhash.to_l1_block_id();
        Ok(L1BlockCommitment::new(block.height() - 1, parent_id))
    }
}

impl MohoStateStore for MohoWorkerContextImpl {
    fn get_latest_moho_state(&self) -> MohoWorkerResult<Option<(L1BlockCommitment, MohoState)>> {
        self.moho_state_db
            .get_latest()
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))
    }

    fn get_moho_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<MohoState> {
        self.moho_state_db
            .get(*blockid)
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))?
            .ok_or(MohoWorkerError::MissingMohoState(*blockid))
    }

    fn store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &MohoState,
    ) -> MohoWorkerResult<()> {
        self.moho_state_db
            .store(*blockid, state.clone())
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))
    }
}

impl ExportEntryStore for MohoWorkerContextImpl {
    fn store_export_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> MohoWorkerResult<()> {
        self.export_entries_db
            .append(container_id, height, entries)
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))
    }

    fn prune_export_entries_from(&self, height: u32) -> MohoWorkerResult<()> {
        self.export_entries_db
            .prune_from(height)
            .map_err(|e| MohoWorkerError::Storage(e.to_string()))
    }
}
