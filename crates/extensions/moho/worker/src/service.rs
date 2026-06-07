//! Service-framework integration for the Moho worker.
//!
//! The worker is an [`AsyncService`] driven by the ASM worker's per-block
//! subscription (a [`Subscription<L1BlockCommitment>`](strata_asm_worker::Subscription)
//! adapted into a [`StreamInput`](strata_service::StreamInput)). Each emitted
//! commitment is folded into a new [`MohoState`](moho_types::MohoState) and
//! persisted.

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use strata_identifiers::L1BlockCommitment;
use strata_service::{AsyncService, Response, Service};

use crate::{MohoWorkerContext, MohoWorkerServiceState};

/// Moho worker service implementation using the service framework.
#[derive(Debug)]
pub struct MohoWorkerService<W> {
    _phantom: PhantomData<W>,
}

impl<W> Service for MohoWorkerService<W>
where
    W: MohoWorkerContext + Send + Sync + 'static,
{
    type State = MohoWorkerServiceState<W>;
    type Msg = L1BlockCommitment;
    type Status = MohoWorkerStatus;

    fn get_status(state: &Self::State) -> Self::Status {
        MohoWorkerStatus {
            is_initialized: true,
            cur_block: Some(state.cur_block()),
            processed: state.processed(),
        }
    }
}

impl<W> AsyncService for MohoWorkerService<W>
where
    W: MohoWorkerContext + Send + Sync + 'static,
{
    async fn process_input(
        state: &mut Self::State,
        input: L1BlockCommitment,
    ) -> anyhow::Result<Response> {
        // The store is synchronous (sled), so the fold runs to completion
        // without yielding. A processing error exits the worker — the commit
        // stream cannot be skipped without leaving a gap.
        state.process(input)?;
        Ok(Response::Continue)
    }
}

/// Status information for the Moho worker service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MohoWorkerStatus {
    pub is_initialized: bool,
    pub cur_block: Option<L1BlockCommitment>,
    pub processed: u64,
}
