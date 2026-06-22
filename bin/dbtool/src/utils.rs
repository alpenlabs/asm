//! CLI argument parsing and the shared `--write` gate.

use anyhow::{Context, Result, anyhow, bail};
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

/// Parses an L1 block commitment formatted as `<height>:<blkid_hex>`.
///
/// `height` is decimal; `blkid_hex` is 32 bytes of hex with an optional `0x`
/// prefix — exactly the shape `dbtool` emits in its `block` field.
pub(crate) fn parse_commitment(s: &str) -> Result<L1BlockCommitment> {
    let (height, blkid) = s.split_once(':').context("expected <height>:<blkid_hex>")?;
    let height: u32 = height.parse().context("invalid height")?;
    let blkid = parse_hash32(blkid)?;
    Ok(L1BlockCommitment::new(
        height,
        L1BlockId::from(Buf32::from(blkid)),
    ))
}

/// Parses a 32-byte value from hex (optional `0x` prefix).
pub(crate) fn parse_hash32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| anyhow!("expected a 32-byte hash, got {len} bytes"))
}

/// Errors unless `--write` was passed, gating every mutating verb.
pub(crate) fn ensure_write(write: bool) -> Result<()> {
    if !write {
        bail!("refusing to mutate without --write; re-run with --write to confirm");
    }
    Ok(())
}
