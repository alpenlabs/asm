//! Handle for interacting with the ASM worker service.

use bitcoin::BlockHash;
use strata_identifiers::L1BlockCommitment;
use strata_service::{CommandHandle, ServiceError, ServiceMonitor};

use crate::{AsmWorkerStatus, WorkerError, message::AsmWorkerMessage};

/// Handle for interacting with the ASM worker service.
#[derive(Debug)]
pub struct AsmWorkerHandle {
    command_handle: CommandHandle<AsmWorkerMessage>,
    monitor: ServiceMonitor<AsmWorkerStatus>,
}

impl AsmWorkerHandle {
    /// Create a new ASM worker handle from a service command handle.
    pub fn new(
        command_handle: CommandHandle<AsmWorkerMessage>,
        monitor: ServiceMonitor<AsmWorkerStatus>,
    ) -> Self {
        Self {
            command_handle,
            monitor,
        }
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
