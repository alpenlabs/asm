//! `asm manifest` — full manifests keyed by L1 block commitment.

use std::fs;

use anyhow::{Result, anyhow, bail};
use asm_storage::SledAsmManifestDb;
use serde_json::{Value, json};
use ssz::{Decode, Encode};
use strata_asm_common::AsmManifest;
use strata_identifiers::L1BlockCommitment;

use crate::{
    cli::{ManifestVerb, PruneArgs},
    output::commitment_json,
    utils::{ensure_write, parse_commitment},
};

pub(crate) fn run(db: &sled::Db, verb: ManifestVerb, write: bool) -> Result<Value> {
    let store = SledAsmManifestDb::open(db)?;
    match verb {
        ManifestVerb::Get { commitment } => {
            let commitment = parse_commitment(&commitment)?;
            Ok(match store.get(&commitment)? {
                Some(manifest) => manifest_json(&manifest),
                None => json!({ "found": false, "block": commitment_json(&commitment) }),
            })
        }
        ManifestVerb::List => {
            let keys = store.list()?;
            Ok(json!({
                "count": keys.len(),
                "entries": keys.iter().map(commitment_json).collect::<Vec<_>>(),
            }))
        }
        ManifestVerb::Put { file } => {
            ensure_write(write)?;
            let bytes = fs::read(&file)?;
            let manifest = AsmManifest::from_ssz_bytes(&bytes)
                .map_err(|e| anyhow!("invalid AsmManifest SSZ: {e:?}"))?;
            store.put(&manifest)?;
            Ok(json!({ "stored": true, "block": commitment_json(&block_of(&manifest)) }))
        }
        ManifestVerb::Delete { commitment } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let deleted = store.delete(&commitment)?;
            Ok(json!({ "deleted": deleted, "block": commitment_json(&commitment) }))
        }
        ManifestVerb::Prune(args) => prune(&store, args, write),
    }
}

fn prune(store: &SledAsmManifestDb, args: PruneArgs, write: bool) -> Result<Value> {
    ensure_write(write)?;
    match (args.before, args.after) {
        (Some(height), None) => {
            store.prune_before(height)?;
            Ok(json!({ "pruned": "before", "height": height }))
        }
        (None, Some(height)) => {
            store.prune_after(height)?;
            Ok(json!({ "pruned": "after", "height": height }))
        }
        _ => bail!("exactly one of --before / --after is required"),
    }
}

/// The block a manifest is keyed by: its own height and block id.
fn block_of(manifest: &AsmManifest) -> L1BlockCommitment {
    L1BlockCommitment::new(manifest.height(), *manifest.blkid())
}

fn manifest_json(manifest: &AsmManifest) -> Value {
    let logs: Vec<String> = manifest
        .logs()
        .iter()
        .map(|log| hex::encode(log.as_bytes()))
        .collect();
    json!({
        "found": true,
        "block": commitment_json(&block_of(manifest)),
        "wtxids_root": hex::encode(manifest.wtxids_root().as_ref()),
        "num_logs": logs.len(),
        "logs": logs,
        "ssz_hex": hex::encode(manifest.as_ssz_bytes()),
    })
}
