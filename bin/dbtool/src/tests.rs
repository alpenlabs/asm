//! Functional tests that drive the `asm` command handlers against a real sled
//! DB populated through `asm-storage` — the same path the runner writes — and
//! assert on the JSON they return.

use asm_storage::{SledAsmManifestDb, SledAsmManifestMmrDb};
use strata_asm_common::{AsmManifest, AsmManifestHash};
use strata_identifiers::{Buf32, L1BlockId, WtxidsRoot};
use tempfile::TempDir;

use crate::{cli::ManifestVerb, cmd};

const HEIGHT: u32 = 100;
const BLKID_SEED: u8 = 0x07;

/// A distinct, non-zero leaf for `seed`: the compact-peaks MMR these proofs
/// verify against treats an all-zero hash as an empty-peak sentinel.
fn leaf(seed: u8) -> AsmManifestHash {
    let mut bytes = [seed; 32];
    bytes[31] = 0xAB;
    AsmManifestHash::from(bytes)
}

/// A storage DB seeded with one manifest (at `HEIGHT`) and four MMR leaves.
///
/// Returns the open `sled::Db` and the `TempDir` backing it; keep both alive.
fn seeded_db() -> (sled::Db, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = sled::open(dir.path()).unwrap();

    let manifests = SledAsmManifestDb::open(&db).unwrap();
    let manifest = AsmManifest::new(
        HEIGHT,
        L1BlockId::from(Buf32::from([BLKID_SEED; 32])),
        WtxidsRoot::from(Buf32::from([0x09; 32])),
        vec![],
    )
    .unwrap();
    manifests.put(&manifest).unwrap();

    let mmr = SledAsmManifestMmrDb::open(&db).unwrap();
    for i in 0..4u8 {
        mmr.put_leaf(i as u64, leaf(i)).unwrap();
    }

    (db, dir)
}

fn commitment_arg(height: u32, seed: u8) -> String {
    format!("{height}:{}", hex::encode([seed; 32]))
}

#[test]
fn manifest_get_returns_block_and_logs() {
    let (db, _dir) = seeded_db();
    let verb = ManifestVerb::Get {
        commitment: commitment_arg(HEIGHT, BLKID_SEED),
    };

    let v = cmd::manifest::run(&db, verb, false).unwrap();

    assert_eq!(v["found"], true);
    assert_eq!(v["block"]["height"], HEIGHT);
    assert_eq!(v["block"]["blkid"], hex::encode([BLKID_SEED; 32]));
    assert_eq!(v["num_logs"], 0);
    assert!(v["ssz_hex"].as_str().is_some_and(|s| !s.is_empty()));
}

#[test]
fn manifest_get_missing_reports_not_found() {
    let (db, _dir) = seeded_db();
    let verb = ManifestVerb::Get {
        commitment: commitment_arg(999, 0x00),
    };

    let v = cmd::manifest::run(&db, verb, false).unwrap();
    assert_eq!(v["found"], false);
}

#[test]
fn manifest_list_counts_entries() {
    let (db, _dir) = seeded_db();

    let v = cmd::manifest::run(&db, ManifestVerb::List, false).unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["entries"][0]["height"], HEIGHT);
}

#[test]
fn delete_without_write_is_refused_and_keeps_data() {
    let (db, _dir) = seeded_db();
    let commitment = commitment_arg(HEIGHT, BLKID_SEED);

    let err = cmd::manifest::run(
        &db,
        ManifestVerb::Delete {
            commitment: commitment.clone(),
        },
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("--write"));

    // The manifest must still be present.
    let v = cmd::manifest::run(&db, ManifestVerb::Get { commitment }, false).unwrap();
    assert_eq!(v["found"], true);
}

#[test]
fn delete_with_write_removes() {
    let (db, _dir) = seeded_db();
    let commitment = commitment_arg(HEIGHT, BLKID_SEED);

    let v = cmd::manifest::run(
        &db,
        ManifestVerb::Delete {
            commitment: commitment.clone(),
        },
        true,
    )
    .unwrap();
    assert_eq!(v["deleted"], true);

    let v = cmd::manifest::run(&db, ManifestVerb::Get { commitment }, false).unwrap();
    assert_eq!(v["found"], false);
}
