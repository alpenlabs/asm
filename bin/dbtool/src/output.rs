//! JSON output helpers.
//!
//! Records are SSZ-encoded and mostly lack structured serde, so each value is
//! rendered as the fields we can cheaply pull from public accessors plus an
//! `ssz_hex` blob carrying the canonical encoding losslessly. That blob is what
//! the `put` verbs consume (hex-decoded), so get → put round-trips.

use anyhow::Result;
use serde_json::{Value, json};
use strata_asm_prover_types::{L1Range, ProofId};
use strata_identifiers::L1BlockCommitment;

/// The `<height>:<blkid_hex>` string the keyed verbs (`get`, `delete`) take as
/// their argument.
pub(crate) fn commitment_str(commitment: &L1BlockCommitment) -> String {
    format!(
        "{}:{}",
        commitment.height(),
        hex::encode(commitment.blkid().as_ref())
    )
}

/// JSON view of an L1 block commitment: `{ "height", "blkid", "commitment" }`.
///
/// `commitment` is the `<height>:<blkid_hex>` string the keyed verbs (`get`,
/// `delete`) take as their argument, so a printed record feeds straight back in
/// without hand-assembling the key from `height` and `blkid`.
pub(crate) fn commitment_json(commitment: &L1BlockCommitment) -> Value {
    json!({
        "height": commitment.height(),
        "blkid": hex::encode(commitment.blkid().as_ref()),
        "commitment": commitment_str(commitment),
    })
}

/// The parseable string form of an L1 range: a single `<commitment>`, or
/// `<start>..=<end>` — what `parse_range` reads back.
pub(crate) fn range_str(range: &L1Range) -> String {
    let start = range.start();
    let end = range.end();
    if start == end {
        commitment_str(&start)
    } else {
        format!("{}..={}", commitment_str(&start), commitment_str(&end))
    }
}

/// JSON view of an L1 range: `{ "start", "end", "range" }`. `range` is the
/// string form that `get`/`delete` take as their argument.
pub(crate) fn range_json(range: &L1Range) -> Value {
    json!({
        "start": commitment_json(&range.start()),
        "end": commitment_json(&range.end()),
        "range": range_str(range),
    })
}

/// The parseable string form of a local proof id: `asm:<range>` or
/// `moho:<commitment>` — what `parse_proof_id` reads back.
pub(crate) fn proof_id_str(id: &ProofId) -> String {
    match id {
        ProofId::Asm(range) => format!("asm:{}", range_str(range)),
        ProofId::Moho(commitment) => format!("moho:{}", commitment_str(commitment)),
    }
}

/// Prints `value` as a single JSON line, or pretty-printed when `pretty`.
pub(crate) fn emit(value: &Value, pretty: bool) -> Result<()> {
    let rendered = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    println!("{rendered}");
    Ok(())
}
