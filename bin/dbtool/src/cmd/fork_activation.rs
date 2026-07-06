//! `asm fork-activation` — discovered fork activations, keyed by enacting
//! height and fork.

use anyhow::Result;
use asm_storage::SledForkActivationDb;
use serde_json::{Value, json};
use strata_asm_common::ForkActivation;

use crate::{
    cli::ForkActivationVerb,
    utils::{ensure_write, parse_fork_id, parse_predicate},
};

pub(crate) fn run(db: &sled::Db, verb: ForkActivationVerb, write: bool) -> Result<Value> {
    let store = SledForkActivationDb::open(db)?;
    match verb {
        ForkActivationVerb::List => {
            let activations = store.list()?;
            Ok(json!({
                "count": activations.len(),
                "entries": activations.iter().map(activation_json).collect::<Vec<_>>(),
            }))
        }
        ForkActivationVerb::Put {
            enacting_height,
            fork,
            predicate,
        } => {
            ensure_write(write)?;
            let activation = ForkActivation {
                enacting_height,
                fork: parse_fork_id(&fork)?,
                new_predicate: parse_predicate(&predicate)?,
            };
            store.put(activation.clone())?;
            Ok(json!({ "stored": true, "activation": activation_json(&activation) }))
        }
        ForkActivationVerb::Prune { after } => {
            ensure_write(write)?;
            store.prune_after(after)?;
            Ok(json!({ "pruned": "after", "height": after }))
        }
    }
}

/// JSON view of an activation. `fork` and `new_predicate` render in the same
/// forms `put` takes as arguments, so a printed record feeds straight back in.
fn activation_json(activation: &ForkActivation) -> Value {
    json!({
        "enacting_height": activation.enacting_height,
        "fork": activation.fork,
        "new_predicate": activation.new_predicate,
        "activation_height": activation.activation_height(),
    })
}
