//! `asm manifest-mmr` — the height-indexed manifest-hash Merkle Mountain Range.

use anyhow::{Result, bail};
use asm_storage::SledAsmManifestMmrDb;
use serde_json::{Value, json};
use ssz::Encode;
use strata_asm_common::AsmManifestHash;

use crate::{
    cli::MmrVerb,
    utils::{ensure_write, parse_hash32},
};

pub(crate) fn run(db: &sled::Db, verb: MmrVerb, write: bool) -> Result<Value> {
    let store = SledAsmManifestMmrDb::open(db)?;
    match verb {
        MmrVerb::Count => Ok(json!({ "leaf_count": store.leaf_count()? })),
        MmrVerb::Leaf { index } => Ok(match store.get_leaf(index)? {
            Some(hash) => {
                json!({ "found": true, "index": index, "hash": hex::encode(hash.as_ref()) })
            }
            None => json!({ "found": false, "index": index }),
        }),
        MmrVerb::Proof { index, at } => {
            // Default to a proof against the whole MMR as it currently stands.
            let at_leaf_count = match at {
                Some(at) => at,
                None => store.leaf_count()?,
            };
            let proof = store.generate_proof(index, at_leaf_count)?;
            let leaf = store
                .get_leaf(index)?
                .map(|hash| hex::encode(hash.as_ref()));
            Ok(json!({
                "index": index,
                "at_leaf_count": at_leaf_count,
                "leaf": leaf,
                "proof_ssz_hex": hex::encode(proof.as_ssz_bytes()),
            }))
        }
        MmrVerb::PutLeaf { height, hash } => {
            ensure_write(write)?;
            let hash = parse_hash32(&hash)?;
            // The compact-peaks MMR these leaves verify against reads an all-zero
            // hash as an empty-peak sentinel, so it isn't a representable leaf —
            // storing one would silently corrupt later proofs.
            if hash == [0u8; 32] {
                bail!("refusing to store an all-zero leaf: it is the MMR's empty-peak sentinel");
            }
            store.put_leaf(height, AsmManifestHash::from(hash))?;
            Ok(json!({ "stored": true, "height": height, "hash": hex::encode(hash) }))
        }
    }
}
