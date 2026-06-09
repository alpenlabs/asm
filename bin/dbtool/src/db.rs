//! Lazy openers for the runner's sled databases.
//!
//! Each invocation opens exactly the one database its command needs. sled takes
//! an exclusive lock on the directory, so opening eagerly (or both at once)
//! would force the operator to point every flag at a path the command does not
//! use, and would clash with a running runner.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Opens the ASM storage sled DB at the required `--storage-db` path.
pub(crate) fn open_storage(path: Option<PathBuf>) -> Result<sled::Db> {
    let path = path.context("--storage-db <path> is required for asm commands")?;
    sled::open(&path).with_context(|| format!("failed to open storage DB at {}", path.display()))
}
