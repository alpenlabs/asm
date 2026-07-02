//! `moho state` — Moho state snapshots keyed by L1 block commitment.
//!
//! Lives in the Moho DB. Unlike an anchor state or manifest, a [`MohoState`]
//! does not carry its own key, so `put` takes the commitment explicitly.

use std::fs;

use anyhow::{Result, anyhow, bail};
use moho_types::MohoState;
use serde_json::{Value, json};
use ssz::{Decode, Encode};
use strata_asm_moho_storage::SledMohoStateDb;
use strata_identifiers::L1BlockCommitment;

use crate::{
    cli::{MohoStateVerb, PruneArgs},
    output::commitment_json,
    utils::{ensure_write, parse_commitment},
};

pub(crate) fn run(db: &sled::Db, verb: MohoStateVerb, write: bool) -> Result<Value> {
    let store = SledMohoStateDb::open(db)?;
    match verb {
        MohoStateVerb::Get { commitment } => {
            let commitment = parse_commitment(&commitment)?;
            Ok(match store.get(commitment)? {
                Some(state) => state_json(&commitment, &state),
                None => json!({ "found": false, "block": commitment_json(&commitment) }),
            })
        }
        MohoStateVerb::Latest => Ok(match store.get_latest()? {
            Some((commitment, state)) => state_json(&commitment, &state),
            None => json!({ "found": false }),
        }),
        MohoStateVerb::List => {
            let keys = store.list()?;
            Ok(json!({
                "count": keys.len(),
                "entries": keys.iter().map(commitment_json).collect::<Vec<_>>(),
            }))
        }
        MohoStateVerb::Put { commitment, file } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let bytes = fs::read(&file)?;
            let state = MohoState::from_ssz_bytes(&bytes)
                .map_err(|e| anyhow!("invalid MohoState SSZ: {e:?}"))?;
            store.store(commitment, state)?;
            Ok(json!({ "stored": true, "block": commitment_json(&commitment) }))
        }
        MohoStateVerb::Delete { commitment } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let deleted = store.delete(&commitment)?;
            Ok(json!({ "deleted": deleted, "block": commitment_json(&commitment) }))
        }
        MohoStateVerb::Prune(args) => prune(&store, args, write),
    }
}

fn prune(store: &SledMohoStateDb, args: PruneArgs, write: bool) -> Result<Value> {
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

fn state_json(commitment: &L1BlockCommitment, state: &MohoState) -> Value {
    json!({
        "found": true,
        "block": commitment_json(commitment),
        "state_commitment": hex::encode(state.compute_commitment().into_inner()),
        "inner_state": hex::encode(state.inner_state().into_inner()),
        "num_export_containers": state.export_state().containers().len(),
        "ssz_hex": hex::encode(state.as_ssz_bytes()),
    })
}
