//! Traits the prover worker uses to interface with the underlying system.
//!
//! The orchestrator's dependencies split into concerns, each backed by a
//! distinct subsystem in production:
//!
//! - Proof persistence and remote-job tracking — reused verbatim from `strata-asm-prover-storage`
//!   ([`ProofDb`], [`RemoteProofMappingDb`], [`RemoteProofStatusDb`], [`MohoStateDb`]).
//! - [`AnchorStateReader`] — reads persisted ASM anchor states.
//! - [`AuxDataReader`] — reads per-block auxiliary data captured during STF execution.
//! - [`L1BlockProvider`] — reads L1 blocks/headers from the Bitcoin source.
//!
//! [`ProverContext`] is the umbrella that combines all of them. It has a blanket
//! impl, so an implementor just implements the concern traits and gets
//! `ProverContext` for free — mirroring
//! [`WorkerContext`](https://docs.rs/strata-asm-worker) in the ASM worker.

use std::error::Error as StdError;

use bitcoin::{Block, block::Header};
use strata_asm_common::{AnchorState, AuxData};
use strata_asm_moho_storage::MohoStateDb;
use strata_asm_prover_storage::{ProofDb, RemoteProofMappingDb, RemoteProofStatusDb};
use strata_identifiers::{L1BlockCommitment, L1BlockId};

use crate::errors::ProverResult;

/// Reads the persisted ASM anchor state for a given L1 block.
pub trait AnchorStateReader {
    /// Fetches the [`AnchorState`] for the block at `blockid`.
    ///
    /// Errors if the state is missing — the orchestrator only requests proofs
    /// for blocks the ASM worker has already processed.
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> ProverResult<AnchorState>;

    /// Fetches the latest persisted [`AnchorState`], if any.
    ///
    /// Used by restart recovery to bound the backfill walk; `None` when no
    /// anchor has been persisted yet. May belong to an abandoned reorg branch,
    /// so callers establish canonicality per height rather than trusting it.
    fn get_latest_anchor_state(&self) -> ProverResult<Option<AnchorState>>;

    /// Reports whether an anchor state is persisted for `blockid`.
    fn contains_anchor_state(&self, blockid: &L1BlockCommitment) -> ProverResult<bool>;
}

/// Reads per-block auxiliary data captured during STF execution.
pub trait AuxDataReader {
    /// Fetches the [`AuxData`] stored for the block at `blockid`.
    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> ProverResult<AuxData>;
}

/// Fetches L1 blocks and headers from the backing Bitcoin source.
///
/// Async because the backing client is async, and the orchestrator drives this
/// from a single-threaded runtime where blocking on the client would deadlock.
pub trait L1BlockProvider {
    /// Fetches the full Bitcoin [`Block`] for `blockid`.
    ///
    /// The future is `Send` so the orchestration loop can run on the
    /// multi-threaded async service framework.
    fn get_l1_block(&self, blockid: &L1BlockId)
    -> impl Future<Output = ProverResult<Block>> + Send;

    /// Fetches just the [`Header`] for `blockid`.
    ///
    /// Used to resolve a block's parent commitment (`prev_blockhash`) without
    /// pulling the full transaction data.
    fn get_l1_block_header(
        &self,
        blockid: &L1BlockId,
    ) -> impl Future<Output = ProverResult<Header>> + Send;

    /// Fetches the height of the current canonical L1 tip.
    ///
    /// Used by restart recovery to clamp the backfill walk to the active chain,
    /// so a persisted block that outranks the current tip (after a reorg to a
    /// shorter chain) is not queried at a height bitcoind no longer has.
    fn get_l1_block_count(&self) -> impl Future<Output = ProverResult<u64>> + Send;

    /// Fetches the canonical L1 block id at `height`.
    fn get_l1_block_hash(
        &self,
        height: u64,
    ) -> impl Future<Output = ProverResult<L1BlockId>> + Send;
}

/// Umbrella context the [`ProverService`](crate::ProverService) runs
/// against.
///
/// Combines proof persistence and remote-job tracking (reused from
/// `strata-asm-prover-storage`), Moho-state reads, and the chain/state reads the
/// [`InputBuilder`](crate::InputBuilder) needs. The blanket impl means any type
/// that implements all of the concern traits automatically implements
/// `ProverContext`, so implementors never name it directly.
///
/// The associated `Error` bounds let the orchestrator wrap storage failures in
/// [`ProverError::Storage`](crate::errors::ProverError::Storage); every concrete
/// backend already satisfies them.
pub trait ProverContext:
    ProofDb<Error: StdError + Send + Sync + 'static>
    + RemoteProofMappingDb<Error: StdError + Send + Sync + 'static>
    + RemoteProofStatusDb<Error: StdError + Send + Sync + 'static>
    + MohoStateDb<Error: StdError + Send + Sync + 'static>
    + AnchorStateReader
    + AuxDataReader
    + L1BlockProvider
{
}

impl<T> ProverContext for T where
    T: ProofDb<Error: StdError + Send + Sync + 'static>
        + RemoteProofMappingDb<Error: StdError + Send + Sync + 'static>
        + RemoteProofStatusDb<Error: StdError + Send + Sync + 'static>
        + MohoStateDb<Error: StdError + Send + Sync + 'static>
        + AnchorStateReader
        + AuxDataReader
        + L1BlockProvider
{
}
