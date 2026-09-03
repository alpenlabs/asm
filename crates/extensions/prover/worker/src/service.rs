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
//! - [`TickMsg::Tick`] — reconcile in-flight remote proofs ([`reconcile`]), then acquire pending
//!   ones: schedule them on the proving backend ([`schedule`]) in generator mode, or fetch them
//!   from the peer asm-runner ([`follow`]) in follower mode.

use std::marker;

use strata_asm_prover_types::ProverStatus;
use strata_service::{AsyncService, Response, Service, TickMsg};
use tracing::{debug, error};
use zkaleido::ZkVmRemoteHost;

use crate::{
    ProverContext, config::ProverMode, errors::ProverResult, follow, message::ProverMessage,
    reconcile, schedule, state::ProverServiceState,
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
            TickMsg::Msg(block) => state.enqueue_block_proofs(block).await,

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

/// Executes one orchestration cycle: reconcile in-flight proofs, then acquire
/// pending ones per the configured [`ProverMode`].
///
/// Reconciliation runs in both modes: a follower may have local jobs in
/// flight from an earlier fallback, and it is a no-op when nothing is.
async fn tick<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    if let Err(error) = state.refresh_proven_frontier().await {
        // Frontier observability stays safely cleared while dirty, but remote
        // job cleanup and scheduling must continue; they have their own
        // retries and may restore the very proof the refresh is looking for.
        error!(?error, "failed to refresh canonical proven frontier");
    }

    if !state.queue.is_empty() {
        debug!(pending = state.queue.len(), "prover tick");
    }

    reconcile::reconcile_active_proofs(state).await?;
    match state.config.mode {
        ProverMode::Generator => schedule::schedule_proofs(state).await?,
        ProverMode::Follower(_) => follow::follow_proofs(state).await?,
    }
    Ok(())
}
