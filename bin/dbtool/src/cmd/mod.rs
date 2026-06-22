//! Command dispatch. One submodule per resource; each returns the JSON value
//! `main` emits.

pub(crate) mod aux;
pub(crate) mod manifest;
pub(crate) mod manifest_mmr;
pub(crate) mod state;

use anyhow::Result;
use serde_json::Value;

use crate::cli::AsmResource;

/// Dispatches an `asm <resource> <verb>` command against the storage DB.
pub(crate) fn run_asm(db: &sled::Db, resource: AsmResource, write: bool) -> Result<Value> {
    match resource {
        AsmResource::State { verb } => state::run(db, verb, write),
        AsmResource::Aux { verb } => aux::run(db, verb, write),
        AsmResource::Manifest { verb } => manifest::run(db, verb, write),
        AsmResource::ManifestMmr { verb } => manifest_mmr::run(db, verb, write),
    }
}
