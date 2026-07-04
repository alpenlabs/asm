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
//! - [`MohoStateStore`] / [`ExportEntryStore`] persist into in-memory maps owned by this context,
//!   mirroring the ASM worker's in-memory test stores.
//!
//! This is the regtest analogue of the `MockContext` the Moho worker's own unit
//! tests use; it lives here (not in the crate's `test_utils`) because it is glued
//! to the harness's [`TestAsmWorkerContext`], which the Moho crate's unit tests
//! have no need for.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bitcoin::BlockHash;
use bitcoind_async_client::traits::Reader;
use moho_types::MohoState;
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_moho_worker::{
    AsmStateProvider, ExportEntryStore, L1ProviderContext, MohoStateStore, MohoWorkerError,
    MohoWorkerResult,
};
use strata_asm_worker::{test_utils::TestAsmWorkerContext, AnchorStateStore};
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_identifiers::L1BlockCommitment;
use tokio::{runtime::Handle, task::block_in_place};

/// One appended export-entry leaf: `(container_id, height, leaf)`.
type ExportEntry = (u8, u32, [u8; 32]);

/// In-memory Moho stores plus a shared handle to the ASM worker's test context.
#[derive(Clone, Debug)]
pub struct TestMohoWorkerContext {
    /// The same context the ASM worker writes to. Anchor states and manifests
    /// (the log source) are read from here.
    asm: TestAsmWorkerContext,
    /// Derived per-block Moho states, plus the latest one, keyed by block.
    moho: Arc<Mutex<MohoStores>>,
    /// Per-container export-entry leaves in MMR-append order.
    export_entries: Arc<Mutex<Vec<ExportEntry>>>,
}

#[derive(Debug, Default)]
struct MohoStores {
    states: HashMap<L1BlockCommitment, MohoState>,
    latest: Option<(L1BlockCommitment, MohoState)>,
}

impl TestMohoWorkerContext {
    /// Wraps `asm` (shared with the running ASM worker) with fresh in-memory Moho
    /// stores.
    pub fn new(asm: TestAsmWorkerContext) -> Self {
        Self {
            asm,
            moho: Arc::new(Mutex::new(MohoStores::default())),
            export_entries: Arc::new(Mutex::new(Vec::new())),
        }
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
        Ok(self.moho.lock().unwrap().latest.clone())
    }

    fn get_moho_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<MohoState> {
        self.moho
            .lock()
            .unwrap()
            .states
            .get(blockid)
            .cloned()
            .ok_or(MohoWorkerError::MissingMohoState(*blockid))
    }

    fn store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &MohoState,
    ) -> MohoWorkerResult<()> {
        let mut stores = self.moho.lock().unwrap();
        stores.states.insert(*blockid, state.clone());
        if stores
            .latest
            .as_ref()
            .is_none_or(|(b, _)| blockid.height() >= b.height())
        {
            stores.latest = Some((*blockid, state.clone()));
        }
        Ok(())
    }
}

impl ExportEntryStore for TestMohoWorkerContext {
    fn store_export_entries(
        &self,
        container_id: u8,
        height: u32,
        entries: Vec<[u8; 32]>,
    ) -> MohoWorkerResult<()> {
        let mut store = self.export_entries.lock().unwrap();
        for entry in entries {
            store.push((container_id, height, entry));
        }
        Ok(())
    }

    fn prune_export_entries_from(&self, height: u32) -> MohoWorkerResult<()> {
        self.export_entries
            .lock()
            .unwrap()
            .retain(|(_, h, _)| *h < height);
        Ok(())
    }
}
