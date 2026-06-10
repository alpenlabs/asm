//! JSON output helpers.
//!
//! Records are SSZ-encoded and mostly lack structured serde, so each value is
//! rendered as the fields we can cheaply pull from public accessors plus an
//! `ssz_hex` blob carrying the canonical encoding losslessly. That blob is what
//! the `put` verbs consume (hex-decoded), so get → put round-trips.

use anyhow::Result;
use serde_json::{Value, json};
use strata_identifiers::L1BlockCommitment;

/// JSON view of an L1 block commitment: `{ "height", "blkid", "commitment" }`.
///
/// `commitment` is the `<height>:<blkid_hex>` string the keyed verbs (`get`,
/// `delete`) take as their argument, so a printed record feeds straight back in
/// without hand-assembling the key from `height` and `blkid`.
pub(crate) fn commitment_json(commitment: &L1BlockCommitment) -> Value {
    let height = commitment.height();
    let blkid = hex::encode(commitment.blkid().as_ref());
    let commitment = format!("{height}:{blkid}");
    json!({
        "height": height,
        "blkid": blkid,
        "commitment": commitment,
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
