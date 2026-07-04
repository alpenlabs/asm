//! Regtest-backed [`MohoWorkerContext`] for the integration harness.
//!
//! The harness runs the Moho worker alongside the ASM worker so integration
//! tests exercise the full ASM → Moho chain. [`TestMohoWorkerContext`] backs the
//! four concern traits the Moho worker interfaces through:
//!
//! - [`AsmStateProvider`] / [`L1ProviderContext`] read from the *same* [`TestAsmWorkerContext`] the
//!   ASM worker writes to (anchor states and their manifests) and the Bitcoin regtest node (parent
//!   resolution). Sharing the ASM context — an `Arc`-backed handle — is what lets the Moho worker
//!   fold the anchor states the ASM worker just committed.
//! - [`MohoStateStore`] / [`ExportEntryStore`] persist through the same sled-backed
//!   [`SledMohoStateDb`] / [`SledExportEntriesDb`] stores the runner uses in production, opened on
//!   a throwaway [`TempDir`]. Backing the tests with the real persistence path (rather than bespoke
//!   in-memory maps) exercises the storage the runner relies on and gives the test the store's real
//!   query surface — e.g. [`find_export_entry`](TestMohoWorkerContext::find_export_entry) to assert
//!   a specific export-entry leaf was mirrored from the fold.
//!
//! This is the regtest analogue of the `MockContext` the Moho worker's own unit
//! tests use; it lives here (not in the crate's `test_utils`) because it is glued
//! to the harness's [`TestAsmWorkerContext`], which the Moho crate's unit tests
//! have no need for.

use std::sync::Arc;

use bitcoin::BlockHash;
use bitcoind_async_client::traits::Reader;
use moho_types::MohoState;
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_moho_storage::{SledExportEntriesDb, SledMohoStateDb};
use strata_asm_moho_worker::{
    AsmStateProvider, ExportEntryStore, L1ProviderContext, MohoStateStore, MohoWorkerError,
    MohoWorkerResult,
};
use strata_asm_worker::{test_utils::TestAsmWorkerContext, AnchorStateStore};
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_identifiers::L1BlockCommitment;
use tempfile::TempDir;
use tokio::{runtime::Handle, task::block_in_place};

/// Sled-backed Moho stores plus a shared handle to the ASM worker's test context.
#[derive(Clone, Debug)]
pub struct TestMohoWorkerContext {
    /// The same context the ASM worker writes to. Anchor states and manifests
    /// (the log source) are read from here.
    asm: TestAsmWorkerContext,
    /// Consolidated sled-backed Moho stores, shared across clones.
    stores: Arc<MohoStores>,
}

/// The sled-backed Moho-state and export-entry stores, plus the sled database
/// and temp dir that back them.
///
/// Consolidated behind one `Arc` (mirroring the ASM worker's test context) so
/// the whole storage lifetime is tied together: the temp dir — and its on-disk
/// data — is deleted when the last clone of the context drops this.
#[derive(Debug)]
struct MohoStores {
    /// Derived per-block Moho states, keyed by L1 block commitment.
    moho_state_db: SledMohoStateDb,
    /// Per-container export-entry leaves mirroring each state's `ExportState` MMR.
    export_entries_db: SledExportEntriesDb,
    /// Backing sled database. Held to keep the trees the stores wrap alive.
    _db: sled::Db,
    /// Temp dir the sled database lives in; deleted when this is dropped.
    _tempdir: TempDir,
}

impl TestMohoWorkerContext {
    /// Wraps `asm` (shared with the running ASM worker) with fresh sled-backed
    /// Moho stores, opened on a throwaway temp directory.
    pub fn new(asm: TestAsmWorkerContext) -> Self {
        let tempdir = tempfile::tempdir().expect("create temp dir for moho sled db");
        let db = sled::open(tempdir.path()).expect("open moho sled db");
        let moho_state_db = SledMohoStateDb::open(&db).expect("open moho state db");
        let export_entries_db = SledExportEntriesDb::open(&db).expect("open export entries db");

        Self {
            asm,
            stores: Arc::new(MohoStores {
                moho_state_db,
                export_entries_db,
                _db: db,
                _tempdir: tempdir,
            }),
        }
    }

    /// Resolves the MMR index of `hash` in `container_id`'s export-entry MMR, or
    /// `None` if the leaf was never appended.
    ///
    /// Lets tests assert a specific export-entry leaf (e.g. an
    /// `OperatorClaimUnlock` hash) was mirrored from the Moho fold into the same
    /// store the runner rebuilds inclusion proofs from.
    pub fn find_export_entry(&self, container_id: u8, hash: &[u8; 32]) -> Option<u64> {
        self.stores
            .export_entries_db
            .find_index(container_id, hash)
            .expect("query export-entry index")
    }
}

impl AsmStateProvider for TestMohoWorkerContext {
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<AnchorState> {
        self.asm
            .get_anchor_state(blockid)
            .map_err(|_| MohoWorkerError::MissingAsmState(*blockid))
    }

    fn get_anchor_logs(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<Vec<AsmLogEntry>> {
        // Logs live in the manifest the ASM worker recorded for the block; an
        // absent manifest (e.g. the genesis anchor, seeded without running the
        // STF) means no logs. The ASM worker records the manifest before it
        // emits the commit the Moho worker folds, so a folded block always has
        // one — matching the harness's own `get_logs_at`.
        Ok(self
            .asm
            .get_manifest(blockid)
            .map(|m| m.logs().to_vec())
            .unwrap_or_default())
    }

    fn get_latest_asm_block(&self) -> MohoWorkerResult<Option<L1BlockCommitment>> {
        Ok(self
            .asm
            .get_latest_anchor_state()
            .map_err(|e| MohoWorkerError::Storage(e.into()))?
            .map(|state| state.last_processed_block()))
    }
}

impl L1ProviderContext for TestMohoWorkerContext {
    fn get_parent_block(&self, block: &L1BlockCommitment) -> MohoWorkerResult<L1BlockCommitment> {
        let block_hash: BlockHash = block.blkid().to_block_hash();
        let client = self.asm.client.clone();
        let fetch = || async move { client.get_block_header(&block_hash).await };

        // Resolve the parent via the regtest node. Same two-context dance as
        // `TestAsmWorkerContext`: `block_in_place` when a runtime is current
        // (the test thread), the stored handle otherwise (the worker's task).
        let header = if Handle::try_current().is_ok() {
            block_in_place(|| self.asm.tokio_handle.block_on(fetch()))
        } else {
            self.asm.tokio_handle.block_on(fetch())
        }
        .map_err(|_| MohoWorkerError::MissingParentBlock(*block))?;

        let parent_id = header.prev_blockhash.to_l1_block_id();
        Ok(L1BlockCommitment::new(block.height() - 1, parent_id))
    }
}

impl MohoStateStore for TestMohoWorkerContext {
    fn get_latest_moho_state(&self) -> MohoWorkerResult<Option<(L1BlockCommitment, MohoState)>> {
        self.stores
            .moho_state_db
            .get_latest()
            .map_err(|e| MohoWorkerError::Storage(e.into()))
    }

    fn get_moho_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<MohoState> {
        self.stores
            .moho_state_db
            .get(*blockid)
            .map_err(|e| MohoWorkerError::Storage(e.into()))?
            .ok_or(MohoWorkerError::MissingMohoState(*blockid))
    }

    fn store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &MohoState,
    ) -> MohoWorkerResult<()> {
        self.stores
            .moho_state_db
            .store(*blockid, state.clone())
            .map_err(|e| MohoWorkerError::Storage(e.into()))
    }
}

impl ExportEntryStore for TestMohoWorkerContext {
    fn store_export_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> MohoWorkerResult<()> {
        self.stores
            .export_entries_db
            .append(container_id, height, entries)
            .map_err(|e| MohoWorkerError::Storage(e.into()))
    }

    fn prune_export_entries_from(&self, height: u32) -> MohoWorkerResult<()> {
        self.stores
            .export_entries_db
            .prune_from(height)
            .map_err(|e| MohoWorkerError::Storage(e.into()))
    }
}
