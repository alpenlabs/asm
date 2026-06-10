//! Clap definitions for the layered `<domain> <resource> <verb>` grammar.
//!
//! The structs/enums here only describe the surface; dispatch lives in
//! [`crate::cmd`] so this module carries no storage dependencies.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Offline inspection and maintenance for ASM storage.
#[derive(Parser, Debug)]
#[command(name = "dbtool", version, about, long_about = None)]
pub(crate) struct Cli {
    /// Path to the sled DB the command operates on. Each command targets exactly
    /// one database — the storage DB for `asm` commands, the proof DB for
    /// `moho`/`proof` commands — so point this at whichever the command needs.
    /// The runner must be stopped: sled takes an exclusive lock on the directory.
    #[arg(long, global = true)]
    pub(crate) db: Option<PathBuf>,

    /// Pretty-print JSON output instead of a single line.
    #[arg(long, global = true)]
    pub(crate) pretty: bool,

    /// Allow mutating verbs (put/delete/prune/put-leaf) to write. Without it,
    /// they refuse to run and the DB is treated as read-only.
    #[arg(long, global = true)]
    pub(crate) write: bool,

    #[command(subcommand)]
    pub(crate) domain: Domain,
}

/// Top-level conceptual domains.
#[derive(Subcommand, Debug)]
pub(crate) enum Domain {
    /// ASM anchor state, aux data, manifests, and the manifest-hash MMR.
    Asm {
        #[command(subcommand)]
        resource: AsmResource,
    },
}

/// Resources within the `asm` domain.
#[derive(Subcommand, Debug)]
pub(crate) enum AsmResource {
    /// Anchor states, keyed by L1 block commitment.
    State {
        #[command(subcommand)]
        verb: StateVerb,
    },
    /// Auxiliary data, keyed by L1 block commitment.
    Aux {
        #[command(subcommand)]
        verb: AuxVerb,
    },
    /// Full manifests, keyed by L1 block commitment.
    Manifest {
        #[command(subcommand)]
        verb: ManifestVerb,
    },
    /// Manifest-hash Merkle Mountain Range (height-indexed).
    #[command(name = "manifest-mmr")]
    ManifestMmr {
        #[command(subcommand)]
        verb: MmrVerb,
    },
}

/// `--before` / `--after` selector shared by the height-pruning verbs.
#[derive(Args, Debug)]
pub(crate) struct PruneArgs {
    /// Remove entries with height strictly below this.
    #[arg(long)]
    pub(crate) before: Option<u32>,
    /// Remove entries with height strictly above this (the height is kept).
    #[arg(long)]
    pub(crate) after: Option<u32>,
}

/// Verbs for `asm state`.
#[derive(Subcommand, Debug)]
pub(crate) enum StateVerb {
    /// Dump the anchor state for a commitment, formatted `<height>:<blkid_hex>`.
    Get { commitment: String },
    /// Dump the highest-height anchor state.
    Latest,
    /// List every stored anchor-state commitment, in height order.
    List,
    /// Store an anchor state from a file of canonical SSZ bytes.
    Put {
        #[arg(long)]
        file: PathBuf,
    },
    /// Delete the anchor state for a commitment `<height>:<blkid_hex>`.
    Delete { commitment: String },
    /// Bulk-remove anchor states by height.
    Prune(PruneArgs),
}

/// Verbs for `asm aux`.
#[derive(Subcommand, Debug)]
pub(crate) enum AuxVerb {
    /// Dump the aux data for a commitment `<height>:<blkid_hex>`.
    Get { commitment: String },
    /// List every stored aux-data commitment, in height order.
    List,
    /// Store aux data for a commitment from a file of canonical SSZ bytes.
    Put {
        commitment: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Delete the aux data for a commitment `<height>:<blkid_hex>`.
    Delete { commitment: String },
    /// Bulk-remove aux data by height.
    Prune(PruneArgs),
}

/// Verbs for `asm manifest`.
#[derive(Subcommand, Debug)]
pub(crate) enum ManifestVerb {
    /// Dump the manifest for a commitment `<height>:<blkid_hex>`.
    Get { commitment: String },
    /// List every stored manifest commitment, in height order.
    List,
    /// Store a manifest from a file of canonical SSZ bytes (key is derived).
    Put {
        #[arg(long)]
        file: PathBuf,
    },
    /// Delete the manifest for a commitment `<height>:<blkid_hex>`.
    Delete { commitment: String },
    /// Bulk-remove manifests by height.
    Prune(PruneArgs),
}

/// Verbs for `asm manifest-mmr`.
///
/// The MMR is height-indexed: the leaf for the L1 block at height `h` is leaf
/// index `h`. So the `<index>` that `leaf`/`proof` read and the `<height>` that
/// `put-leaf` writes are the same value, just named for each verb's vantage.
#[derive(Subcommand, Debug)]
pub(crate) enum MmrVerb {
    /// Print the current leaf count.
    Count,
    /// Print the manifest hash at a leaf index (the L1 height).
    Leaf { index: u64 },
    /// Generate an inclusion proof for a leaf against an MMR of `--at` leaves
    /// (defaults to the current leaf count).
    Proof {
        index: u64,
        #[arg(long)]
        at: Option<u64>,
    },
    /// Write a manifest hash as the leaf at `height` (append or overwrite).
    PutLeaf { height: u64, hash: String },
}
