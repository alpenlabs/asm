//! Lazy openers for the runner's sled databases.
//!
//! Each invocation opens exactly the one database its command needs. sled takes
//! an exclusive lock on the directory, so opening eagerly (or both at once)
//! would force the operator to point every flag at a path the command does not
//! use, and would clash with a running runner.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Opens the ASM sled DB at the required `--db` path.
///
/// Backs the `asm` commands (anchor state, aux data, manifests, and the
/// manifest-hash MMR).
pub(crate) fn open_asm(path: Option<PathBuf>) -> Result<sled::Db> {
    open_at(path, "ASM")
}

/// Opens the proof sled DB at the required `--db` path.
///
/// Backs the `proof` commands. The runner points this at its own
/// `proof_db_path`, which it shares with the Moho state store.
pub(crate) fn open_proof(path: Option<PathBuf>) -> Result<sled::Db> {
    open_at(path, "proof")
}

/// Opens an existing sled DB at `path`, rejecting anything that is not one.
///
/// `dbtool` only ever inspects or maintains a database the runner already
/// created, so a path that is not one is an operator mistake (a typo, the wrong
/// directory). We reject it up front rather than let `sled::open` materialize a
/// fresh empty DB — which would make reads report `found: false` and writes
/// mutate the wrong place. `purpose` names the database in the diagnostics.
///
/// Both checks are needed. `sled::open` creates a database in whatever
/// directory it is handed, so testing only for the directory would still leave
/// sled files behind in an unrelated one that happens to exist — even for a
/// read-only command, which fails afterwards on its own emptiness.
fn open_at(path: Option<PathBuf>, purpose: &str) -> Result<sled::Db> {
    let path = path.with_context(|| format!("--db <path> is required for {purpose} commands"))?;
    if !path.is_dir() {
        bail!(
            "no sled DB at {}: expected an existing directory (dbtool never creates one)",
            path.display()
        );
    }
    // Every sled database has a `conf` at its root, so its absence means this
    // directory is something else.
    if !path.join("conf").is_file() {
        bail!(
            "no sled DB at {}: the directory exists but holds no sled database \
             (dbtool never creates one)",
            path.display()
        );
    }
    sled::open(&path).with_context(|| format!("failed to open {purpose} DB at {}", path.display()))
}
