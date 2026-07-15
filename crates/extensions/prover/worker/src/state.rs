//! Service state for the prover worker.

use strata_asm_prover_types::{L1Range, ProofId};
use strata_identifiers::L1BlockCommitment;
use strata_service::ServiceState;
use tracing::{debug, info};
use zkaleido::ZkVmRemoteHost;

use crate::{
    ProverContext, config::OrchestratorConfig, constants, errors::ProverResult,
    input::InputBuilder, queue::PendingProofQueue,
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

    /// Most recent block the ASM worker reported as committed. Surfaced through
    /// [`ProverStatus`](crate::service::ProverStatus) for observability.
    pub(crate) last_committed: Option<L1BlockCommitment>,
}

impl<C, H> ProverServiceState<C, H>
where
    C: ProverContext + Send + Sync,
{
    /// Creates the service state, seeding the pending queue with the proofs of
    /// the latest worker-processed block — mirroring how the ASM worker
    /// resumes from its stored anchor state at construction.
    ///
    /// The commit subscription only delivers blocks the worker processes after
    /// subscribing, so proofs pending at shutdown would otherwise sit
    /// unrecovered until the next new L1 block arrives. The single seed is
    /// sufficient: the scheduler pulls a deferred proof's missing
    /// prerequisites back into the queue, recursively walking the chain down
    /// to the last block that already has a Moho proof. Already-completed or
    /// already-submitted proofs are filtered out by the scheduler, so this
    /// only resurrects the genuinely-missing work.
    ///
    /// The latest anchor may sit on an abandoned reorg branch (orphaned states
    /// are never pruned). That is acceptable for a seed: its ancestry still
    /// covers all history shared with the canonical chain, and any
    /// canonical-only blocks are pulled in by the cascade when the next
    /// commit arrives.
    pub(crate) fn new(
        ctx: C,
        asm: H,
        moho: H,
        config: OrchestratorConfig,
        input_builder: InputBuilder,
    ) -> ProverResult<Self> {
        let mut queue = PendingProofQueue::new();
        if let Some(latest) = ctx.get_latest_anchor_state()? {
            let seed = latest.chain_view.pow_state.last_verified_block;
            // Proofs exist only above genesis; seeding a Moho proof at or
            // below it would leave the scheduler chasing prerequisites that
            // can never be built.
            if seed.height() > input_builder.genesis().height() {
                info!(%seed, "seeding proof recovery from latest processed block");
                queue.enqueue(ProofId::Asm(L1Range::single(seed)));
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
            last_committed: None,
        })
    }

    /// Expands a committed block into the proofs it requires and enqueues them.
    ///
    /// Each committed [`L1BlockCommitment`] maps to one ASM step proof and one
    /// Moho recursive proof. Scheduling happens on the next tick; this only
    /// records the work.
    pub(crate) fn enqueue_block_proofs(&mut self, block: L1BlockCommitment) {
        debug!(%block, "ASM worker committed block, enqueuing proofs");
        self.queue.enqueue(ProofId::Asm(L1Range::single(block)));
        self.queue.enqueue(ProofId::Moho(block));
        self.last_committed = Some(block);
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
