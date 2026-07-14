//! Handle for interacting with the ASM worker service.

use bitcoin::BlockHash;
use strata_identifiers::L1BlockCommitment;
use strata_service::{CommandHandle, ServiceError, ServiceMonitor};

use crate::{
    AsmWorkerStatus, Subscribers, Subscription, WorkerError, WorkerResult,
    message::AsmWorkerMessage,
};

/// Handle for interacting with the ASM worker service.
#[derive(Debug)]
pub struct AsmWorkerHandle {
    command_handle: CommandHandle<AsmWorkerMessage>,
    monitor: ServiceMonitor<AsmWorkerStatus>,
    subscribers: Subscribers<L1BlockCommitment>,
}

impl AsmWorkerHandle {
    /// Create a new ASM worker handle from a service command handle.
    ///
    /// `subscribers` is the same registry the service state emits into, so
    /// handles created here can hand out [`Subscription`]s wired to the worker.
    pub(crate) fn new(
        command_handle: CommandHandle<AsmWorkerMessage>,
        monitor: ServiceMonitor<AsmWorkerStatus>,
        subscribers: Subscribers<L1BlockCommitment>,
    ) -> Self {
        Self {
            command_handle,
            monitor,
            subscribers,
        }
    }

    /// Subscribes to per-block notifications.
    ///
    /// Returns a [`Subscription`] that yields each [`L1BlockCommitment`] the
    /// worker commits, starting from the next commit after this call. There is
    /// no replay: register before the worker begins processing the blocks you
    /// care about (the bootstrap order enforces this).
    pub fn subscribe_blocks(&self) -> Subscription<L1BlockCommitment> {
        self.subscribers.subscribe()
    }

    /// Sends an L1 block hash to the ASM service and waits for processing to
    /// complete. Returns the commitments the worker processed (oldest first),
    /// which may span several blocks the worker walked back through.
    pub fn submit_block(&self, block: BlockHash) -> WorkerResult<Vec<L1BlockCommitment>> {
        self.command_handle
            .send_and_wait_blocking(|completion| AsmWorkerMessage::SubmitBlock(block, completion))
            .map_err(convert_service_error)?
    }

    /// Async variant of [`submit_block`](Self::submit_block).
    pub async fn submit_block_async(
        &self,
        block: BlockHash,
    ) -> WorkerResult<Vec<L1BlockCommitment>> {
        self.command_handle
            .send_and_wait(|completion| AsmWorkerMessage::SubmitBlock(block, completion))
            .await
            .map_err(convert_service_error)?
    }

    /// Allows other services to listen to status updates.
    pub fn monitor(&self) -> &ServiceMonitor<AsmWorkerStatus> {
        &self.monitor
    }

    /// Returns the number of pending inputs that have not been processed yet.
    pub fn pending(&self) -> usize {
        self.command_handle.pending()
    }
}

/// Convert service framework errors to worker errors.
///
/// The two "worker exited" cases map to the dedicated [`WorkerError::WorkerExited`]
/// (that's the meaning callers key off). Every other framework failure is carried
/// verbatim by [`WorkerError::Service`], preserving the concrete `ServiceError` in
/// the source chain rather than flattening it to a string.
fn convert_service_error(err: ServiceError) -> WorkerError {
    match err {
        ServiceError::WorkerExited | ServiceError::WorkerExitedWithoutResponse => {
            WorkerError::WorkerExited
        }
        other => WorkerError::Service(other),
    }
}
