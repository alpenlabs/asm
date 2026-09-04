//! CLI argument parsing and the shared `--write` gate.

use anyhow::{Context, Result, anyhow, bail};
use strata_asm_prover_types::{L1Range, ProofId, RemoteProofId};
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

/// Parses an L1 block range: `<commitment>` (a single block) or
/// `<commitment>..<commitment>` (inclusive start..end).
///
/// Accepts the `..=` the range prints with as well as a plain `..`, so a printed
/// `range` field copies straight back into `get`/`delete`.
pub(crate) fn parse_range(s: &str) -> Result<L1Range> {
    match s.split_once("..") {
        Some((start, end)) => {
            let start = parse_commitment(start)?;
            // Tolerate the `..=` form the range renders with.
            let end = parse_commitment(end.strip_prefix('=').unwrap_or(end))?;
            L1Range::new(start, end).context("range end height is below its start")
        }
        None => Ok(L1Range::single(parse_commitment(s)?)),
    }
}

/// Parses a remote proof id from hex (optional `0x` prefix). The id is opaque
/// bytes assigned by the remote prover, so any length is accepted.
pub(crate) fn parse_remote_id(s: &str) -> Result<RemoteProofId> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(RemoteProofId(hex::decode(s).context("invalid hex")?))
}

/// Parses a local proof id: `asm:<range>` or `moho:<commitment>` — the form the
/// `proof_id` field prints, so it round-trips.
pub(crate) fn parse_proof_id(s: &str) -> Result<ProofId> {
    let (kind, rest) = s
        .split_once(':')
        .context("expected asm:<range> or moho:<commitment>")?;
    match kind {
        "asm" => Ok(ProofId::Asm(parse_range(rest)?)),
        "moho" => Ok(ProofId::Moho(parse_commitment(rest)?)),
        other => bail!("unknown proof id kind {other:?}: expected `asm` or `moho`"),
    }
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
