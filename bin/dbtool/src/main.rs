//! `dbtool` — offline inspection and maintenance for ASM storage.
//!
//! A layered `<domain> <resource> <verb>` CLI over the ASM runner's sled
//! databases, modeled on alpen's `strata-dbtool` but built in the layered
//! grammar STR-3564 recommends rather than a flat verb-prefixed surface.
//!
//! Covers the `asm` domain (ASM DB: anchor state, aux data, manifests, and the
//! manifest-hash MMR), the `moho` domain (Moho DB: state snapshots and the
//! export-entry index), and the `proof` domain (proof DB: ASM/Moho proofs and
//! the remote-prover bookkeeping). See `README.md`.
//!
//! Output is JSON on stdout; errors go to stderr. The tool opens sled read-only
//! by intent: mutating verbs refuse to run without `--write`. sled takes an
//! exclusive lock on the directory, so the runner must be stopped.

mod cli;
mod cmd;
mod db;
mod output;
mod utils;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Domain};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let Cli {
        db,
        pretty,
        write,
        domain,
    } = Cli::parse();

    let value = match domain {
        Domain::Asm { resource } => {
            let db = db::open_asm(db)?;
            cmd::run_asm(&db, resource, write)?
        }
        Domain::Moho { resource } => {
            let db = db::open_moho(db)?;
            cmd::run_moho(&db, resource, write)?
        }
        Domain::Proof { resource } => {
            let db = db::open_proof(db)?;
            cmd::run_proof(&db, resource, write)?
        }
    };

    output::emit(&value, pretty)
}
