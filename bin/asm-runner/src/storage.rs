//! Storage setup for the ASM runner.
//!
//! The runner persists into three independent sled databases: the ASM DB
//! (anchor states, aux data, manifests, and the manifest-hash MMR), the Moho
//! DB (Moho state snapshots and the per-container export-entry index), and —
//! only when the orchestrator is configured — the proof DB (ASM/Moho proofs
//! and the remote-prover bookkeeping).

use std::{path::Path, sync::Arc};

use anyhow::Result;
use asm_storage::{
    SledAsmAuxDataDb, SledAsmHandoverDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb,
};
use strata_asm_moho_storage::{SledExportEntriesDb, SledMohoStateDb};
use strata_asm_prover_storage::SledProofDb;

/// ASM storage backends, all opened on the ASM sled database.
pub(crate) struct AsmStorage {
    pub state_db: Arc<SledAsmStateDb>,
    pub aux_db: Arc<SledAsmAuxDataDb>,
    pub handover_db: Arc<SledAsmHandoverDb>,
    pub manifest_db: Arc<SledAsmManifestDb>,
    pub mmr_db: Arc<SledAsmManifestMmrDb>,
}

/// Moho storage backends, both opened on the Moho sled database.
pub(crate) struct MohoStorage {
    pub state_db: SledMohoStateDb,
    pub export_entries_db: SledExportEntriesDb,
}

/// Create the ASM storage backends.
pub(crate) fn create_asm_storage(path: &Path) -> Result<AsmStorage> {
    let db = sled::open(path)?;
    Ok(AsmStorage {
        state_db: Arc::new(SledAsmStateDb::open(&db)?),
        aux_db: Arc::new(SledAsmAuxDataDb::open(&db)?),
        handover_db: Arc::new(SledAsmHandoverDb::open(&db)?),
        manifest_db: Arc::new(SledAsmManifestDb::open(&db)?),
        mmr_db: Arc::new(SledAsmManifestMmrDb::open(&db)?),
    })
}

/// Create the Moho storage backends.
pub(crate) fn create_moho_storage(path: &Path) -> Result<MohoStorage> {
    let db = sled::open(path)?;
    let state_db = SledMohoStateDb::open(&db)?;
    let export_entries_db = SledExportEntriesDb::open(&db)?;
    state_db.recover_rebase(&export_entries_db)?;
    Ok(MohoStorage {
        state_db,
        export_entries_db,
    })
}

/// Create the proof storage backend.
pub(crate) fn create_proof_storage(path: &Path) -> Result<SledProofDb> {
    let db = sled::open(path)?;
    Ok(SledProofDb::open(&db)?)
}
