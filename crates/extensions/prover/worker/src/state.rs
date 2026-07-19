//! Service state for the prover worker.

use std::sync::Arc;

use strata_asm_prover_types::{L1Range, ProofId};
use strata_identifiers::L1BlockCommitment;
use strata_service::ServiceState;
use tracing::{debug, info};
use zkaleido::ZkVmRemoteHost;

use crate::{
    ProverContext,
    config::OrchestratorConfig,
    constants,
    errors::{ProverError, ProverResult},
    input::InputBuilder,
    peer::ProofPeer,
    queue::PendingProofQueue,
};

/// Service state for the prover worker.
///
/// Holds everything the [`ProverService`](crate::service::ProverService) mutates
/// or reads while processing inputs: the storage/chain context, the remote host
/// pair, the input builder, and the in-memory pending-proof queue. Generic over
/// the prover context `C` and the remote host `H`, mirroring how
/// [`AsmWorkerServiceState`](https://docs.rs/strata-asm-worker) is generic over
/// its worker context and ASM spec.
#[derive(Debug)]
pub struct ProverServiceState<C, H> {
    /// Context the service reads storage and chain data through.
    pub(crate) ctx: C,

    /// Remote host for ASM step proofs.
    pub(crate) asm: H,

    /// Remote host for Moho recursive proofs.
    pub(crate) moho: H,

    /// Orchestration tuning (tick interval, concurrency limit).
    pub(crate) config: OrchestratorConfig,

    /// Assembles ZkVM inputs for each proof type.
    pub(crate) input_builder: InputBuilder,

    /// Proofs awaiting submission to the remote prover.
    pub(crate) queue: PendingProofQueue,

    /// Most recent block the Moho worker committed. Initialized from the
    /// latest persisted Moho state at construction and advanced by the commit
    /// subscription. Surfaced through
    /// [`ProverStatus`](crate::service::ProverStatus) for observability.
    pub(crate) last_committed: Option<L1BlockCommitment>,

    /// Highest block with a completed Moho recursive proof. Initialized from
    /// the proof store at construction and advanced as reconciliation stores
    /// newly completed proofs. Surfaced through
    /// [`ProverStatus`](crate::service::ProverStatus) for observability.
    pub(crate) last_proven: Option<L1BlockCommitment>,

    /// Peer proof source; present iff the worker runs in
    /// [`ProverMode::Follower`](crate::config::ProverMode::Follower).
    pub(crate) peer: Option<Arc<dyn ProofPeer + Send + Sync>>,

    /// Consecutive failed peer status probes (follower mode). Reset on the
    /// first successful probe.
    pub(crate) peer_failures: u32,
}

impl<C, H> ProverServiceState<C, H>
where
    C: ProverContext + Send + Sync,
{
    /// Creates the service state, seeding the pending queue with the Moho
    /// proof of the latest Moho-worker-committed block — mirroring how the
    /// workers resume from their stored state at construction.
    ///
    /// The latest Moho state is the exact watermark of the commit stream that
    /// drives the prover, and that stream only delivers blocks committed after
    /// subscribing — so proofs pending at shutdown would otherwise sit
    /// unrecovered until the next new L1 block arrives. The single seed is
    /// sufficient: the scheduler pulls a deferred proof's missing
    /// prerequisites back into the queue, recursively walking the chain down
    /// to the last block that already has a Moho proof. Already-completed or
    /// already-submitted proofs are filtered out by the scheduler, so this
    /// only resurrects the genuinely-missing work.
    ///
    /// The latest Moho state may sit on an abandoned reorg branch (orphaned
    /// states are never pruned). That is acceptable for a seed: its ancestry
    /// still covers all history shared with the canonical chain, and any
    /// canonical-only blocks are pulled in by the cascade when the next
    /// commit arrives.
    pub(crate) async fn new(
        ctx: C,
        asm: H,
        moho: H,
        config: OrchestratorConfig,
        input_builder: InputBuilder,
        peer: Option<Arc<dyn ProofPeer + Send + Sync>>,
    ) -> ProverResult<Self> {
        let last_committed = ctx
            .get_latest_moho_state()
            .await
            .map_err(|e| ProverError::storage("failed to fetch latest moho state", e))?
            .map(|(block, _)| block);
        let last_proven = ctx
            .get_latest_moho_proof()
            .await
            .map_err(|e| ProverError::storage("failed to fetch latest moho proof", e))?
            .map(|(block, _)| block);

        let mut queue = PendingProofQueue::new();
        if let Some(seed) = last_committed {
            // Nothing to recover when the committed tip is already proven.
            // Compare blocks, not heights: an orphaned proof can outrank the
            // committed tip after a reorg to a shorter chain.
            //
            // Proofs exist only above genesis; seeding a Moho proof at or
            // below it would leave the scheduler chasing prerequisites that
            // can never be built.
            if last_proven != Some(seed) && seed.height() > input_builder.genesis().height() {
                info!(%seed, "seeding proof recovery from latest committed block");
                // The Moho proof alone is enough: its ASM step proof, if
                // missing, is pulled in by the prerequisite cascade.
                queue.enqueue(ProofId::Moho(seed));
            }
        }

        Ok(Self {
            ctx,
            asm,
            moho,
            config,
            input_builder,
            queue,
            last_committed,
            last_proven,
            peer,
            peer_failures: 0,
        })
    }

    /// Expands a committed block into the proofs it requires and enqueues them.
    ///
    /// Each committed [`L1BlockCommitment`] maps to one ASM step proof and one
    /// Moho recursive proof. Scheduling happens on the next tick; this only
    /// records the work.
    pub(crate) fn enqueue_block_proofs(&mut self, block: L1BlockCommitment) {
        debug!(%block, "moho worker committed block, enqueuing proofs");
        self.queue.enqueue(ProofId::Asm(L1Range::single(block)));
        self.queue.enqueue(ProofId::Moho(block));
        self.last_committed = Some(block);
    }

    /// Advances the proven frontier if `proof_id` is a Moho proof above it.
    ///
    /// Called whenever a completed Moho proof lands in the proof store —
    /// whether reconciled from the remote prover or fetched from a peer.
    pub(crate) fn advance_proven(&mut self, proof_id: &ProofId) {
        if let ProofId::Moho(block) = proof_id
            && self
                .last_proven
                .is_none_or(|cur| block.height() > cur.height())
        {
            self.last_proven = Some(*block);
        }
    }
}

impl<C, H> ServiceState for ProverServiceState<C, H>
where
    C: ProverContext + Send + Sync + 'static,
    H: ZkVmRemoteHost + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        constants::SERVICE_NAME
    }
}
