//! `proof` — ASM/Moho proofs and the remote-prover bookkeeping (proof DB).
//!
//! Proof values are borsh-encoded (each wraps a `ProofReceiptWithMetadata`), so
//! records carry a lossless `borsh_hex` blob rather than the `ssz_hex` the `asm`
//! records use. Remote-prover ids are opaque bytes, rendered and parsed as hex.

use anyhow::Result;
use serde_json::{Value, json};
use strata_asm_prover_storage::SledProofDb;
use strata_asm_prover_types::{AsmProof, L1Range, MohoProof, ProofId, RemoteProofId};
use strata_identifiers::L1BlockCommitment;
use zkaleido::RemoteProofStatus;

use crate::{
    cli::{ProofAsmVerb, ProofMappingVerb, ProofMohoVerb, ProofResource, ProofStatusVerb},
    output::{commitment_json, commitment_str, proof_id_str, range_json, range_str},
    utils::{ensure_write, parse_commitment, parse_proof_id, parse_range, parse_remote_id},
};

pub(crate) fn run(db: &sled::Db, resource: ProofResource, write: bool) -> Result<Value> {
    let store = SledProofDb::open(db)?;
    match resource {
        ProofResource::Asm { verb } => asm(&store, verb, write),
        ProofResource::Moho { verb } => moho(&store, verb, write),
        ProofResource::Mapping { verb } => mapping(&store, verb),
        ProofResource::Status { verb } => status(&store, verb, write),
        ProofResource::Prune { before } => {
            ensure_write(write)?;
            store.prune_before(before)?;
            Ok(json!({ "pruned": "before", "height": before }))
        }
    }
}

fn asm(store: &SledProofDb, verb: ProofAsmVerb, write: bool) -> Result<Value> {
    match verb {
        ProofAsmVerb::Get { range } => {
            let range = parse_range(&range)?;
            Ok(match store.get_asm(&range)? {
                Some(proof) => asm_proof_json(&range, &proof),
                None => json!({ "found": false, "range": range_json(&range) }),
            })
        }
        ProofAsmVerb::List => {
            let ranges = store.list_asm()?;
            Ok(json!({
                "count": ranges.len(),
                "entries": ranges.iter().map(range_json).collect::<Vec<_>>(),
            }))
        }
        ProofAsmVerb::Delete { range } => {
            ensure_write(write)?;
            let range = parse_range(&range)?;
            let deleted = store.delete_asm(&range)?;
            Ok(json!({ "deleted": deleted, "range": range_json(&range) }))
        }
    }
}

fn moho(store: &SledProofDb, verb: ProofMohoVerb, write: bool) -> Result<Value> {
    match verb {
        ProofMohoVerb::Get { commitment } => {
            let commitment = parse_commitment(&commitment)?;
            Ok(match store.get_moho(&commitment)? {
                Some(proof) => moho_proof_json(&commitment, &proof),
                None => json!({ "found": false, "block": commitment_json(&commitment) }),
            })
        }
        ProofMohoVerb::Latest => Ok(match store.get_latest_moho()? {
            Some((commitment, proof)) => moho_proof_json(&commitment, &proof),
            None => json!({ "found": false }),
        }),
        ProofMohoVerb::List => {
            let keys = store.list_moho()?;
            Ok(json!({
                "count": keys.len(),
                "entries": keys.iter().map(commitment_json).collect::<Vec<_>>(),
            }))
        }
        ProofMohoVerb::Delete { commitment } => {
            ensure_write(write)?;
            let commitment = parse_commitment(&commitment)?;
            let deleted = store.delete_moho(&commitment)?;
            Ok(json!({ "deleted": deleted, "block": commitment_json(&commitment) }))
        }
    }
}

fn mapping(store: &SledProofDb, verb: ProofMappingVerb) -> Result<Value> {
    match verb {
        ProofMappingVerb::GetRemote { proof_id } => {
            let id = parse_proof_id(&proof_id)?;
            Ok(match store.get_remote(id)? {
                Some(remote) => json!({
                    "found": true,
                    "proof_id": proof_id_str(&id),
                    "remote_id": hex::encode(&remote.0),
                }),
                None => json!({ "found": false, "proof_id": proof_id_str(&id) }),
            })
        }
        ProofMappingVerb::GetLocal { remote_id } => {
            let remote = parse_remote_id(&remote_id)?;
            Ok(match store.get_local(&remote)? {
                Some(id) => json!({
                    "found": true,
                    "remote_id": hex::encode(&remote.0),
                    "proof_id": proof_id_str(&id),
                }),
                None => json!({ "found": false, "remote_id": hex::encode(&remote.0) }),
            })
        }
        ProofMappingVerb::List => {
            let mappings = store.list_mappings()?;
            Ok(json!({
                "count": mappings.len(),
                "entries": mappings
                    .iter()
                    .map(|(local, remote)| mapping_json(local, remote))
                    .collect::<Vec<_>>(),
            }))
        }
    }
}

fn status(store: &SledProofDb, verb: ProofStatusVerb, write: bool) -> Result<Value> {
    match verb {
        ProofStatusVerb::Get { remote_id } => {
            let remote = parse_remote_id(&remote_id)?;
            Ok(match store.status(&remote)? {
                Some(status) => json!({
                    "found": true,
                    "remote_id": hex::encode(&remote.0),
                    "status": status_json(&status),
                }),
                None => json!({ "found": false, "remote_id": hex::encode(&remote.0) }),
            })
        }
        ProofStatusVerb::List => status_list(store.list_status()?),
        ProofStatusVerb::InProgress => status_list(store.in_progress()?),
        ProofStatusVerb::Delete { remote_id } => {
            ensure_write(write)?;
            let remote = parse_remote_id(&remote_id)?;
            let deleted = store.delete_status(&remote)?;
            Ok(json!({ "deleted": deleted, "remote_id": hex::encode(&remote.0) }))
        }
    }
}

fn status_list(entries: Vec<(RemoteProofId, RemoteProofStatus)>) -> Result<Value> {
    Ok(json!({
        "count": entries.len(),
        "entries": entries
            .iter()
            .map(|(remote, status)| json!({
                "remote_id": hex::encode(&remote.0),
                "status": status_json(status),
            }))
            .collect::<Vec<_>>(),
    }))
}

fn mapping_json(local: &ProofId, remote: &RemoteProofId) -> Value {
    json!({
        "proof_id": proof_id_str(local),
        "remote_id": hex::encode(&remote.0),
    })
}

/// Structured JSON for a remote proof status (e.g. `"Requested"` or
/// `{"Failed":{"Other":"…"}}`), via its serde encoding.
fn status_json(status: &RemoteProofStatus) -> Value {
    serde_json::to_value(status).unwrap_or(Value::Null)
}

fn asm_proof_json(range: &L1Range, proof: &AsmProof) -> Value {
    json!({
        "found": true,
        "range": range_json(range),
        "range_str": range_str(range),
        "borsh_hex": hex::encode(borsh::to_vec(&proof.0).expect("borsh serialization should not fail")),
    })
}

fn moho_proof_json(commitment: &L1BlockCommitment, proof: &MohoProof) -> Value {
    json!({
        "found": true,
        "block": commitment_json(commitment),
        "commitment": commitment_str(commitment),
        "borsh_hex": hex::encode(borsh::to_vec(&proof.0).expect("borsh serialization should not fail")),
    })
}
