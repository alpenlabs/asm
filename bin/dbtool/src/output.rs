//! JSON output helpers.
//!
//! Records are SSZ-encoded and mostly lack structured serde, so each value is
//! rendered as the fields we can cheaply pull from public accessors plus an
//! `ssz_hex` blob carrying the canonical encoding losslessly. That blob is what
//! the `put` verbs consume (hex-decoded), so get → put round-trips.

use anyhow::Result;
use serde_json::{Value, json};
use strata_identifiers::L1BlockCommitment;

/// JSON view of an L1 block commitment: `{ "height", "blkid" }`.
pub(crate) fn commitment_json(commitment: &L1BlockCommitment) -> Value {
    json!({
        "height": commitment.height(),
        "blkid": hex::encode(commitment.blkid().as_ref()),
    })
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
