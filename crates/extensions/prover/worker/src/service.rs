//! Service framework integration for the prover worker.
//!
//! Mirrors the ASM worker (`strata-asm-worker`): a logic-only [`ProverService`]
//! ZST implements the framework traits, while all mutable data lives in
//! [`ProverServiceState`]. The service is driven by the framework's input loop,
//! fed by a [`TickingInput`](strata_service::TickingInput) that merges the ASM
//! worker's commit subscription with a periodic wakeup tick:
//!
//! - [`TickMsg::Msg`] — a newly committed block; expand it into its ASM step and Moho recursive
//!   proofs and enqueue them.
//! - [`TickMsg::Tick`] — reconcile in-flight remote proofs ([`reconcile`]), then schedule pending
//!   ones ([`schedule`]).

use std::marker;

use serde::{Deserialize, Serialize};
use strata_asm_prover_types::{L1Range, ProofId};
use strata_identifiers::L1BlockCommitment;
use strata_service::{AsyncService, Response, Service, TickMsg};
use tracing::{debug, error, info};
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

/// Executes one orchestration cycle: recover pending proofs (once), reconcile
/// in-flight proofs, then schedule pending ones.
async fn tick<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    // Rebuild the pending queue from durable state on the first tick after
    // startup. The commit subscription only re-delivers blocks the worker
    // reprocesses, and an already-processed block is a no-op on restart — so
    // proofs pending but never submitted (e.g. a Moho proof deferred on a
    // missing prerequisite) would otherwise be lost, stalling the recursive
    // chain behind the gap forever.
    //
    // Recovery is the only path that re-enqueues those blocks, so a transient
    // failure (Bitcoin RPC or sled) must not leave the queue permanently short.
    // Retry once per tick until it succeeds rather than proceeding with a
    // half-rebuilt queue; `proofs_to_backfill` is all-or-nothing (it errors
    // before enqueuing anything), so each retry is clean and the successful run
    // enqueues exactly once.
    if !state.recovered {
        match recover_pending_proofs(state).await {
            Ok(()) => state.recovered = true,
            Err(e) => error!(?e, "failed to recover pending proofs; retrying next tick"),
        }
    }

    if !state.queue.is_empty() {
        debug!(pending = state.queue.len(), "prover tick");
    }

    reconcile::reconcile_active_proofs(state).await?;
    schedule::schedule_proofs(state).await?;
    Ok(())
}

/// Re-enqueues proofs that were pending at restart but are not yet completed or
/// in flight.
///
/// Enumerates every worker-processed canonical block above the highest canonical
/// block that already has a Moho proof (see [`InputBuilder`](crate::input::InputBuilder)'s
/// `proofs_to_backfill`) and enqueues its ASM and Moho proof requests.
/// Already-completed or already-submitted proofs are filtered out downstream by
/// the scheduler's `try_submit`, so this only resurrects the genuinely-missing
/// work.
async fn recover_pending_proofs<C, H>(state: &mut ProverServiceState<C, H>) -> ProverResult<()>
where
    C: ProverContext + Send + Sync,
    H: ZkVmRemoteHost + Send + Sync,
{
    let backfill = state.input_builder.proofs_to_backfill(&state.ctx).await?;

    if backfill.is_empty() {
        return Ok(());
    }

    info!(
        blocks = backfill.len(),
        "re-enqueuing pending proofs after restart"
    );
    for commitment in backfill {
        state
            .queue
            .enqueue(ProofId::Asm(L1Range::single(commitment)));
        state.queue.enqueue(ProofId::Moho(commitment));
    }
    Ok(())
}

/// Status snapshot for the prover service, surfaced through the
/// [`ServiceMonitor`](strata_service::ServiceMonitor) on
/// [`ProverWorkerHandle`](crate::ProverWorkerHandle).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverStatus {
    /// Number of proofs queued but not yet submitted to the remote prover.
    pub pending: usize,

    /// Most recent block the ASM worker reported as committed, if any.
    pub last_committed: Option<L1BlockCommitment>,
}
