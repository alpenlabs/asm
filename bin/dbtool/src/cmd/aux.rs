//! `asm aux` — auxiliary data keyed by L1 block commitment.

use std::fs;

use anyhow::{Result, anyhow, bail};
use asm_storage::SledAsmAuxDataDb;
use serde_json::{Value, json};
use ssz::{Decode, Encode};
use strata_asm_common::AuxData;

use crate::{
    cli::{AuxVerb, PruneArgs},
    output::commitment_json,
    utils::{ensure_write, parse_commitment},
};

pub(crate) fn run(db: &sled::Db, verb: AuxVerb, write: bool) -> Result<Value> {
    let store = SledAsmAuxDataDb::open(db)?;
    match verb {
        AuxVerb::Get { commitment } => {
            let commitment = parse_commitment(&commitment)?;
            Ok(match store.get(&commitment)? {
                Some(data) => json!({
                    "found": true,
                    "block": commitment_json(&commitment),
                    "ssz_hex": hex::encode(data.as_ssz_bytes()),
                }),
                None => json!({ "found": false, "block": commitment_json(&commitment) }),
            })
        }
        AuxVerb::List => {
            let keys = store.list()?;
            Ok(json!({
                "count": keys.len(),
                "entries": keys.iter().map(commitment_json).collect::<Vec<_>>(),
            }))
        }
        AuxVerb::Put { commitment, file } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let bytes = fs::read(&file)?;
            let data = AuxData::from_ssz_bytes(&bytes)
                .map_err(|e| anyhow!("invalid AuxData SSZ: {e:?}"))?;
            store.put(&commitment, &data)?;
            Ok(json!({ "stored": true, "block": commitment_json(&commitment) }))
        }
        AuxVerb::Delete { commitment } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let deleted = store.delete(&commitment)?;
            Ok(json!({ "deleted": deleted, "block": commitment_json(&commitment) }))
        }
        AuxVerb::Prune(args) => prune(&store, args, write),
    }
}

fn prune(store: &SledAsmAuxDataDb, args: PruneArgs, write: bool) -> Result<Value> {
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
