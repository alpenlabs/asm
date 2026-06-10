//! `asm state` — anchor states keyed by L1 block commitment.

use std::fs;

use anyhow::{Result, anyhow, bail};
use asm_storage::SledAsmStateDb;
use serde_json::{Value, json};
use ssz::{Decode, Encode};
use strata_asm_common::AnchorState;
use strata_identifiers::L1BlockCommitment;

use crate::{
    cli::{PruneArgs, StateVerb},
    output::commitment_json,
    utils::{ensure_write, parse_commitment},
};

pub(crate) fn run(db: &sled::Db, verb: StateVerb, write: bool) -> Result<Value> {
    let store = SledAsmStateDb::open(db)?;
    match verb {
        StateVerb::Get { commitment } => {
            let commitment = parse_commitment(&commitment)?;
            Ok(match store.get(&commitment)? {
                Some(state) => state_json(&state),
                None => json!({ "found": false, "block": commitment_json(&commitment) }),
            })
        }
        StateVerb::Latest => Ok(match store.get_latest()? {
            Some(state) => state_json(&state),
            None => json!({ "found": false }),
        }),
        StateVerb::List => {
            let keys = store.list()?;
            Ok(json!({
                "count": keys.len(),
                "entries": keys.iter().map(commitment_json).collect::<Vec<_>>(),
            }))
        }
        StateVerb::Put { file } => {
            ensure_write(write)?;
            let bytes = fs::read(&file)?;
            let state = AnchorState::from_ssz_bytes(&bytes)
                .map_err(|e| anyhow!("invalid AnchorState SSZ: {e:?}"))?;
            store.put(&state)?;
            Ok(json!({ "stored": true, "block": commitment_json(block_of(&state)) }))
        }
        StateVerb::Delete { commitment } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let deleted = store.delete(&commitment)?;
            Ok(json!({ "deleted": deleted, "block": commitment_json(&commitment) }))
        }
        StateVerb::Prune(args) => prune(&store, args, write),
    }
}

fn prune(store: &SledAsmStateDb, args: PruneArgs, write: bool) -> Result<Value> {
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

/// The block a state is keyed by: its own `last_verified_block`.
fn block_of(state: &AnchorState) -> &L1BlockCommitment {
    &state.chain_view.pow_state.last_verified_block
}

fn state_json(state: &AnchorState) -> Value {
    json!({
        "found": true,
        "block": commitment_json(block_of(state)),
        "ssz_hex": hex::encode(state.as_ssz_bytes()),
    })
}
