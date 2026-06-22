//! Unit tests for argument parsing.
//!
//! Behavioral coverage of the command handlers — reads, writes, the `--write`
//! gate, prune dispatch, and round-trips — lives in the `functional-tests`
//! `tests/dbtool` suite, which drives the real binary against a DB the runner
//! actually wrote. Only the pure parsing helpers, which need no DB, are unit
//! tested here.

use crate::utils;

#[test]
fn parse_commitment_accepts_height_and_hex_blkid() {
    let blkid = "07".repeat(32);
    assert!(utils::parse_commitment(&format!("100:{blkid}")).is_ok());
    // The blkid hex may carry an optional `0x` prefix.
    assert!(utils::parse_commitment(&format!("100:0x{blkid}")).is_ok());
}

#[test]
fn parse_commitment_rejects_malformed_input() {
    assert!(utils::parse_commitment("nocolon").is_err()); // no ':' separator
    assert!(utils::parse_commitment("notanumber:00").is_err()); // non-decimal height
    assert!(utils::parse_commitment(&format!("100:{}", "zz".repeat(32))).is_err()); // bad hex
    assert!(utils::parse_commitment("100:00").is_err()); // blkid not 32 bytes
}

#[test]
fn parse_hash32_enforces_length_and_prefix() {
    let hash = "11".repeat(32);
    assert!(utils::parse_hash32(&hash).is_ok());
    assert!(utils::parse_hash32(&format!("0x{hash}")).is_ok());
    assert!(utils::parse_hash32("00").is_err()); // too short
    assert!(utils::parse_hash32(&"11".repeat(33)).is_err()); // too long
    assert!(utils::parse_hash32("zz").is_err()); // not hex
}
