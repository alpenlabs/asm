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
    /// Proofs and remote-prover bookkeeping (proof DB).
    Proof {
        #[command(subcommand)]
        resource: ProofResource,
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

/// Resources within the `proof` domain — all in the proof DB.
#[derive(Subcommand, Debug)]
pub(crate) enum ProofResource {
    /// ASM step proofs, keyed by L1 block range.
    Asm {
        #[command(subcommand)]
        verb: ProofAsmVerb,
    },
    /// Moho recursive proofs, keyed by L1 block commitment.
    Moho {
        #[command(subcommand)]
        verb: ProofMohoVerb,
    },
    /// Bidirectional local↔remote proof-id mapping.
    Mapping {
        #[command(subcommand)]
        verb: ProofMappingVerb,
    },
    /// Execution status of in-flight remote proof jobs.
    Status {
        #[command(subcommand)]
        verb: ProofStatusVerb,
    },
    /// Bulk-remove everything held below a height: ASM and Moho proofs, their
    /// local↔remote id mappings, and the status rows of the jobs that produced
    /// them.
    Prune {
        /// Remove proofs with (start) height strictly below this.
        #[arg(long)]
        before: u32,
    },
}

/// Verbs for `proof asm`. A `<range>` is `<commitment>` (single block) or
/// `<commitment>..<commitment>` (inclusive start..end).
#[derive(Subcommand, Debug)]
pub(crate) enum ProofAsmVerb {
    /// Dump the ASM proof for a range.
    Get { range: String },
    /// List every stored ASM proof range, in ascending order.
    List,
    /// Delete the ASM proof for a range.
    Delete { range: String },
}

/// Verbs for `proof moho`.
#[derive(Subcommand, Debug)]
pub(crate) enum ProofMohoVerb {
    /// Dump the Moho proof anchored at a commitment `<height>:<blkid_hex>`.
    Get { commitment: String },
    /// Dump the highest-height Moho proof.
    Latest,
    /// List every stored Moho proof anchor, in height order.
    List,
    /// Delete the Moho proof for a commitment `<height>:<blkid_hex>`.
    Delete { commitment: String },
}

/// Verbs for `proof mapping`.
///
/// A `<proof_id>` is `asm:<range>` or `moho:<commitment>`; a `<remote_id>` is
/// the opaque remote id as hex.
#[derive(Subcommand, Debug)]
pub(crate) enum ProofMappingVerb {
    /// Resolve the remote id a local proof id maps to.
    GetRemote { proof_id: String },
    /// Resolve the local proof id a remote id maps to.
    GetLocal { remote_id: String },
    /// List every stored `(local, remote)` mapping.
    List,
    /// Delete both directions of the mapping for a local proof id, freeing it
    /// to be submitted to the remote prover again.
    Delete { proof_id: String },
}

/// Verbs for `proof status`. A `<remote_id>` is the opaque remote id as hex.
#[derive(Subcommand, Debug)]
pub(crate) enum ProofStatusVerb {
    /// Dump the tracked status of a remote proof.
    Get { remote_id: String },
    /// List every tracked `(remote_id, status)`.
    List,
    /// List only the active (`Requested` / `InProgress`) jobs.
    #[command(name = "in-progress")]
    InProgress,
    /// Delete the status entry for a remote proof.
    Delete { remote_id: String },
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
    /// Resolve the `mmr_index` of `hash_hex` within `container`. Duplicate
    /// hashes are legal; when leaves share a hash this resolves to the most
    /// recently appended one.
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
    /// concatenated raw hashes (length must be a multiple of 32). A hash the
    /// container already stores may be appended again — `find` then resolves
    /// to the newest leaf.
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
