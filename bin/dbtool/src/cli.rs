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
    /// Path to the sled DB the command operates on. Each domain targets exactly
    /// one database — the ASM DB for `asm`, the Moho DB for `moho`, the proof
    /// DB for the planned `proof` — so point this at whichever the
    /// command needs. The runner must be stopped: sled takes an exclusive lock
    /// on the directory.
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
    /// Moho state snapshots and the per-container export-entry MMR.
    Moho {
        #[command(subcommand)]
        resource: MohoResource,
    },
}

/// Resources within the `moho` domain. Both live in the Moho DB, so `--db`
/// points at the same directory for either resource.
#[derive(Subcommand, Debug)]
pub(crate) enum MohoResource {
    /// Moho state snapshots, keyed by L1 block commitment.
    State {
        #[command(subcommand)]
        verb: MohoStateVerb,
    },
    /// Per-container export-entry MMR mirroring the ExportState leaves.
    #[command(name = "export-entries")]
    ExportEntries {
        #[command(subcommand)]
        verb: ExportEntriesVerb,
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

/// Verbs for `moho state`.
///
/// `MohoState` does not carry its own key, so `put` takes the commitment
/// explicitly (unlike `asm state put`, which derives it from the record).
#[derive(Subcommand, Debug)]
pub(crate) enum MohoStateVerb {
    /// Dump the Moho state for a commitment `<height>:<blkid_hex>`.
    Get { commitment: String },
    /// Dump the highest-height Moho state.
    Latest,
    /// List every stored Moho-state commitment, in height order.
    List,
    /// Store a Moho state for a commitment from a file of canonical SSZ bytes.
    Put {
        commitment: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Delete the Moho state for a commitment `<height>:<blkid_hex>`.
    Delete { commitment: String },
    /// Bulk-remove Moho states by height.
    Prune(PruneArgs),
}

/// Verbs for `moho export-entries`.
///
/// Each container (`<container>`, a `u8`) is an independent MMR over its entry
/// hashes. The `<index>` a leaf sits at is its `mmr_index` within that
/// container.
#[derive(Subcommand, Debug)]
pub(crate) enum ExportEntriesVerb {
    /// Print the entry hash at `(container, index)`.
    Get { container: u8, index: u64 },
    /// Resolve the `mmr_index` of `hash_hex` within `container`.
    Find { container: u8, hash: String },
    /// Print the L1 height at which the leaf at `(container, index)` was inserted.
    Height { container: u8, index: u64 },
    /// Print the number of entries stored for `container`.
    Count { container: u8 },
    /// Print the half-open leaf-index range `container` gained at `height`.
    Range { container: u8, height: u32 },
    /// Generate an inclusion proof for a leaf against the container's MMR at
    /// `--at` leaves (defaults to the container's current entry count).
    Proof {
        container: u8,
        index: u64,
        #[arg(long)]
        at: Option<u64>,
    },
    /// Append 32-byte entry hashes for `container` at `height` from a file of
    /// concatenated raw hashes (length must be a multiple of 32).
    Append {
        container: u8,
        height: u32,
        #[arg(long)]
        file: PathBuf,
    },
    /// Remove every entry inserted at `--from <height>` or above, across all
    /// containers.
    Prune(PruneFromArgs),
}

/// `--from` selector for the export-entries prune verb, whose semantics (remove
/// at or above a height, across all containers) differ from the state store's
/// `--before` / `--after`.
#[derive(Args, Debug)]
pub(crate) struct PruneFromArgs {
    /// Remove entries inserted at this height or above.
    #[arg(long)]
    pub(crate) from: u32,
}
