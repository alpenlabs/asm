//! Command dispatch. One submodule per resource; each returns the JSON value
//! `main` emits.

pub(crate) mod aux_input;
pub(crate) mod export_entries;
pub(crate) mod manifest;
pub(crate) mod manifest_mmr;
pub(crate) mod moho_state;
pub(crate) mod proof;
pub(crate) mod state;

use anyhow::Result;
use serde_json::Value;

use crate::cli::{AsmResource, MohoResource, ProofResource};

/// Dispatches an `asm <resource> <verb>` command against the ASM DB.
pub(crate) fn run_asm(db: &sled::Db, resource: AsmResource, write: bool) -> Result<Value> {
    match resource {
        AsmResource::State { verb } => state::run(db, verb, write),
        AsmResource::Aux { verb } => aux_input::run(db, verb, write),
        AsmResource::Manifest { verb } => manifest::run(db, verb, write),
        AsmResource::ManifestMmr { verb } => manifest_mmr::run(db, verb, write),
    }
}

/// Dispatches a `moho <resource> <verb>` command against the Moho DB.
pub(crate) fn run_moho(db: &sled::Db, resource: MohoResource, write: bool) -> Result<Value> {
    match resource {
        MohoResource::State { verb } => moho_state::run(db, verb, write),
        MohoResource::ExportEntries { verb } => export_entries::run(db, verb, write),
    }
}

/// Dispatches a `proof <resource> <verb>` command against the proof DB.
pub(crate) fn run_proof(db: &sled::Db, resource: ProofResource, write: bool) -> Result<Value> {
    proof::run(db, resource, write)
}
