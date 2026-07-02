//! `moho export-entries` — the per-container export-entry MMR.
//!
//! Lives in the Moho DB. Each container is an independent MMR over its entry
//! hashes; a leaf's `<index>` is its `mmr_index` within that container.

use std::{fs, path::Path};

use anyhow::{Result, bail};
use serde_json::{Value, json};
use ssz::Encode;
use strata_asm_moho_storage::SledExportEntriesDb;

use crate::{
    cli::{ExportEntriesVerb, PruneFromArgs},
    utils::{ensure_write, parse_hash32},
};

pub(crate) fn run(db: &sled::Db, verb: ExportEntriesVerb, write: bool) -> Result<Value> {
    let store = SledExportEntriesDb::open(db)?;
    match verb {
        ExportEntriesVerb::Get { container, index } => Ok(match store.get(container, index)? {
            Some(hash) => {
                json!({ "found": true, "container": container, "index": index, "hash": hex::encode(hash) })
            }
            None => json!({ "found": false, "container": container, "index": index }),
        }),
        ExportEntriesVerb::Find { container, hash } => {
            let hash = parse_hash32(&hash)?;
            Ok(match store.find_index(container, &hash)? {
                Some(index) => {
                    json!({ "found": true, "container": container, "hash": hex::encode(hash), "index": index })
                }
                None => {
                    json!({ "found": false, "container": container, "hash": hex::encode(hash) })
                }
            })
        }
        ExportEntriesVerb::Height { container, index } => {
            Ok(match store.entry_height(container, index)? {
                Some(height) => {
                    json!({ "found": true, "container": container, "index": index, "height": height })
                }
                None => json!({ "found": false, "container": container, "index": index }),
            })
        }
        ExportEntriesVerb::Count { container } => {
            Ok(json!({ "container": container, "count": store.num_entries(container)? }))
        }
        ExportEntriesVerb::Range { container, height } => {
            Ok(match store.leaf_range_at_height(container, height)? {
                Some(range) => json!({
                    "found": true,
                    "container": container,
                    "height": height,
                    "start": range.start,
                    "end": range.end,
                }),
                None => json!({ "found": false, "container": container, "height": height }),
            })
        }
        ExportEntriesVerb::Proof {
            container,
            index,
            at,
        } => {
            // Default to a proof against the container's MMR as it currently stands.
            let at_leaf_count = match at {
                Some(at) => at,
                None => store.num_entries(container)?,
            };
            let proof = store.generate_proof(container, index, at_leaf_count)?;
            let leaf = store.get(container, index)?.map(hex::encode);
            Ok(json!({
                "container": container,
                "index": index,
                "at_leaf_count": at_leaf_count,
                "leaf": leaf,
                "proof_ssz_hex": hex::encode(proof.as_ssz_bytes()),
            }))
        }
        ExportEntriesVerb::Append {
            container,
            height,
            file,
        } => {
            ensure_write(write)?;
            let entries = read_hashes(&file)?;
            let count = entries.len();
            store.append(container, height, entries)?;
            Ok(json!({ "appended": count, "container": container, "height": height }))
        }
        ExportEntriesVerb::Prune(PruneFromArgs { from }) => {
            ensure_write(write)?;
            store.prune_from(from)?;
            Ok(json!({ "pruned": "from", "height": from }))
        }
    }
}

/// Reads a file of concatenated raw 32-byte entry hashes into leaves.
///
/// Mirrors how the worker hands a block's leaves over in one batched append; the
/// file must be a whole number of 32-byte hashes.
fn read_hashes(file: &Path) -> Result<Vec<[u8; 32]>> {
    let bytes = fs::read(file)?;
    if bytes.len() % 32 != 0 {
        bail!(
            "entry file length {} is not a multiple of 32 bytes",
            bytes.len()
        );
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("chunk is 32 bytes"))
        .collect())
}
