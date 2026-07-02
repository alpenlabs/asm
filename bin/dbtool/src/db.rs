//! Lazy openers for the runner's sled databases.
//!
//! Each invocation opens exactly the one database its command needs. sled takes
//! an exclusive lock on the directory, so opening eagerly (or several at once)
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

/// Opens the Moho sled DB at the required `--db` path.
///
/// Backs the `moho` commands (state snapshots and the export-entry index
/// share one directory).
pub(crate) fn open_moho(path: Option<PathBuf>) -> Result<sled::Db> {
    open_at(path, "Moho")
}

/// Opens an existing sled DB at `path`, rejecting a missing directory.
///
/// `dbtool` only ever inspects or maintains a database the runner already
/// created, so a missing path is an operator mistake (a typo, the wrong
/// directory). We reject it up front rather than let `sled::open` materialize a
/// fresh empty DB — which would make reads report `found: false` and writes
/// mutate the wrong place. `purpose` names the database in the diagnostics.
fn open_at(path: Option<PathBuf>, purpose: &str) -> Result<sled::Db> {
    let path = path.with_context(|| format!("--db <path> is required for {purpose} commands"))?;
    if !path.is_dir() {
        bail!(
            "no sled DB at {}: expected an existing directory (dbtool never creates one)",
            path.display()
        );
    }
    sled::open(&path).with_context(|| format!("failed to open {purpose} DB at {}", path.display()))
}
