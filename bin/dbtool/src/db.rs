//! Lazy openers for the runner's sled databases.
//!
//! Each invocation opens exactly the one database its command needs. sled takes
//! an exclusive lock on the directory, so opening eagerly (or both at once)
//! would force the operator to point every flag at a path the command does not
//! use, and would clash with a running runner.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Opens the ASM storage sled DB at the required `--db` path.
///
/// `dbtool` only ever inspects or maintains a database the runner already
/// created, so a missing path is an operator mistake (a typo, the wrong
/// directory). We reject it up front rather than let `sled::open` materialize a
/// fresh empty DB — which would make reads report `found: false` and writes
/// mutate the wrong place.
pub(crate) fn open_storage(path: Option<PathBuf>) -> Result<sled::Db> {
    let path = path.context("--db <path> is required for asm commands")?;
    if !path.is_dir() {
        bail!(
            "no sled DB at {}: expected an existing directory (dbtool never creates one)",
            path.display()
        );
    }
    sled::open(&path).with_context(|| format!("failed to open storage DB at {}", path.display()))
}
