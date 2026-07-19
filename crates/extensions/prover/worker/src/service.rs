//! Service framework integration for the prover worker.
//!
//! Mirrors the ASM worker (`strata-asm-worker`): a logic-only [`ProverService`]
//! ZST implements the framework traits, while all mutable data lives in
//! [`ProverServiceState`]. The service is driven by the framework's input loop,
//! fed by a [`TickingInput`](strata_service::TickingInput) that merges the Moho
//! worker's commit subscription with a periodic wakeup tick:
//!
//! - [`TickMsg::Msg`] — a newly committed block; expand it into its ASM step and Moho recursive
//!   proofs and enqueue them.
//! - [`TickMsg::Tick`] — reconcile in-flight remote proofs ([`reconcile`]), then schedule pending
//!   ones ([`schedule`]).

use std::marker;

use serde::{Deserialize, Serialize};
use strata_identifiers::L1BlockCommitment;
use strata_service::{AsyncService, Response, Service, TickMsg};
use tracing::{debug, error};
use zkaleido::ZkVmRemoteHost;

use crate::{
    ProverContext, errors::ProverResult, message::ProverMessage, reconcile, schedule,
    state::ProverServiceState,
};

/// Prover service implementation using the service framework.
///
/// A zero-sized logic holder generic over the prover context `C` and the remote
/// host `H`; all state lives in [`ProverServiceState`].
#[derive(Debug)]
pub struct ProverService<C, H> {
    _phantom: marker::PhantomData<(C, H)>,
}

impl<C, H> Service for ProverService<C, H>
where
    C: ProverContext + Send + Sync + 'static,
    H: ZkVmRemoteHost + Send + Sync + 'static,
{
    type State = ProverServiceState<C, H>;
    type Msg = ProverMessage;
    type Status = ProverStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        ProverStatus {
            pending: state.queue.len(),
            last_committed: state.last_committed,
            last_proven: state.last_proven,
        }
    }
}

impl<C, H> AsyncService for ProverService<C, H>
where
    C: ProverContext + Send + Sync + 'static,
    H: ZkVmRemoteHost + Send + Sync + 'static,
{
    async fn process_input(state: &mut Self::State, input: Self::Msg) -> anyhow::Result<Response> {
        match input {
            // A newly committed block: record the proofs it requires. Scheduling
            // happens on the next tick.
            TickMsg::Msg(block) => state.enqueue_block_proofs(block),

            // Periodic wakeup: drive reconcile + schedule. Transient failures are
            // logged and swallowed so the service keeps running, matching the
            // pre-framework orchestrator loop.
            TickMsg::Tick => {
                if let Err(e) = tick(state).await {
                    error!(?e, "prover tick failed");
                }
            }
        }
        Ok(Response::Continue)
    }
}

/// Executes one orchestration cycle: reconcile in-flight proofs, then schedule
/// pending ones.
async fn tick<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    if !state.queue.is_empty() {
        debug!(pending = state.queue.len(), "prover tick");
    }

    reconcile::reconcile_active_proofs(state).await?;
    schedule::schedule_proofs(state).await?;
    Ok(())
}

/// Status snapshot for the prover service, surfaced through the
/// [`ServiceMonitor`](strata_service::ServiceMonitor) on
/// [`ProverWorkerHandle`](crate::ProverWorkerHandle).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverStatus {
    /// Number of proofs queued but not yet submitted to the remote prover.
    pub pending: usize,

    /// Most recent block the Moho worker committed, if any — from the current
    /// session's commit subscription, or persisted state after a restart.
    pub last_committed: Option<L1BlockCommitment>,

    /// Highest block with a completed Moho recursive proof, if any. The gap
    /// between this and `last_committed` is the work still in flight or
    /// pending.
    pub last_proven: Option<L1BlockCommitment>,
}
