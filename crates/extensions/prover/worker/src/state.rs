//! Service state for the prover worker.

use strata_asm_prover_types::{L1Range, ProofId};
use strata_identifiers::L1BlockCommitment;
use strata_service::ServiceState;
use tracing::debug;
use zkaleido::ZkVmRemoteHost;

use crate::{
    ProverContext, config::OrchestratorConfig, constants, input::InputBuilder,
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

    /// Most recent block the ASM worker reported as committed. Surfaced through
    /// [`ProverStatus`](crate::service::ProverStatus) for observability.
    pub(crate) last_committed: Option<L1BlockCommitment>,
}

impl<C, H> ProverServiceState<C, H> {
    /// Creates a new service state with an empty pending queue.
    pub(crate) fn new(
        ctx: C,
        asm: H,
        moho: H,
        config: OrchestratorConfig,
        input_builder: InputBuilder,
    ) -> Self {
        Self {
            ctx,
            asm,
            moho,
            config,
            input_builder,
            queue: PendingProofQueue::new(),
            last_committed: None,
        }
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
