//! Messages from the handle to the worker.

use strata_identifiers::L1BlockCommitment;
use strata_service::CommandCompletionSender;

use crate::{AsmState, WorkerResult};

/// Messages from the ASM Handle to the subprotocol to give it work to do.
#[derive(Debug)]
pub enum SubprotocolMessage {
    NewAsmState(AsmState, L1BlockCommitment),
}

/// Messages from the handle to the ASM worker, with a completion sender to
/// return the processing result.
#[derive(Debug)]
pub enum AsmWorkerMessage {
    /// Submit an L1 block for ASM processing. The completion sender receives
    /// the result once the block has been fully processed.
    SubmitBlock(L1BlockCommitment, CommandCompletionSender<WorkerResult<()>>),
}
