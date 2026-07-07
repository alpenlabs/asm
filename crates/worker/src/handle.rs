//! Handle for interacting with the ASM worker service.

use bitcoin::BlockHash;
use strata_identifiers::L1BlockCommitment;
use strata_service::{CommandHandle, ServiceError, ServiceMonitor};

use crate::{AsmWorkerStatus, Subscribers, Subscription, WorkerError, message::AsmWorkerMessage};

/// Handle for interacting with the ASM worker service.
#[derive(Debug)]
pub struct AsmWorkerHandle {
    command_handle: CommandHandle<AsmWorkerMessage>,
    monitor: ServiceMonitor<AsmWorkerStatus>,
    subscribers: Subscribers<L1BlockCommitment>,
    genesis_block: L1BlockCommitment,
}

impl AsmWorkerHandle {
    /// Create a new ASM worker handle from a service command handle.
    ///
    /// `subscribers` is the same registry the service state emits into, so
    /// handles created here can hand out [`Subscription`]s wired to the worker.
    /// `genesis_block` is the L1 block the genesis anchor is pinned to.
    pub(crate) fn new(
        command_handle: CommandHandle<AsmWorkerMessage>,
        monitor: ServiceMonitor<AsmWorkerStatus>,
        subscribers: Subscribers<L1BlockCommitment>,
        genesis_block: L1BlockCommitment,
    ) -> Self {
        Self {
            command_handle,
            monitor,
            subscribers,
            genesis_block,
        }
    }

    /// The L1 block the genesis anchor is pinned to.
    ///
    /// The worker is the component that owns the params, so downstream
    /// services needing the chain's genesis point (the Moho worker, the
    /// prover input builder) read it from here.
    pub fn genesis_block(&self) -> L1BlockCommitment {
        self.genesis_block
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
    pub fn submit_block(&self, block: BlockHash) -> anyhow::Result<Vec<L1BlockCommitment>> {
        self.command_handle
            .send_and_wait_blocking(|completion| AsmWorkerMessage::SubmitBlock(block, completion))
            .map_err(convert_service_error)?
            .map_err(Into::into)
    }

    /// Async variant of [`submit_block`](Self::submit_block).
    pub async fn submit_block_async(
        &self,
        block: BlockHash,
    ) -> anyhow::Result<Vec<L1BlockCommitment>> {
        self.command_handle
            .send_and_wait(|completion| AsmWorkerMessage::SubmitBlock(block, completion))
            .await
            .map_err(convert_service_error)?
            .map_err(Into::into)
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
fn convert_service_error(err: ServiceError) -> WorkerError {
    match err {
        ServiceError::WorkerExited | ServiceError::WorkerExitedWithoutResponse => {
            WorkerError::WorkerExited
        }
        ServiceError::WaitCancelled => {
            WorkerError::Unexpected("operation was cancelled".to_string())
        }
        ServiceError::BlockingThreadPanic(msg) => {
            WorkerError::Unexpected(format!("blocking thread panicked: {msg}"))
        }
        ServiceError::UnknownInputErr => WorkerError::Unexpected("unknown input error".to_string()),
    }
}
