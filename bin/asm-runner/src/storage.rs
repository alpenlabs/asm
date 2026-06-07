//! Storage setup for the ASM runner.

use std::sync::Arc;

use anyhow::Result;
use asm_storage::{
    ExportEntriesDb, SledAsmAuxDataDb, SledAsmManifestDb, SledAsmManifestMmrDb, SledAsmStateDb,
};

use crate::config::DatabaseConfig;

/// Storage backends for the ASM runner, all opened on a single sled database.
pub(crate) struct Storage {
    pub state_db: Arc<SledAsmStateDb>,
    pub aux_db: Arc<SledAsmAuxDataDb>,
    pub manifest_db: Arc<SledAsmManifestDb>,
    pub mmr_db: Arc<SledAsmManifestMmrDb>,
    pub export_entries_db: ExportEntriesDb,
}

/// Create storage backends for the ASM runner.
pub(crate) fn create_storage(config: &DatabaseConfig) -> Result<Storage> {
    let db = sled::open(&config.path)?;
    Ok(Storage {
        state_db: Arc::new(SledAsmStateDb::open(&db)?),
        aux_db: Arc::new(SledAsmAuxDataDb::open(&db)?),
        manifest_db: Arc::new(SledAsmManifestDb::open(&db)?),
        mmr_db: Arc::new(SledAsmManifestMmrDb::open(&db)?),
        export_entries_db: ExportEntriesDb::open(&db)?,
    })
}
