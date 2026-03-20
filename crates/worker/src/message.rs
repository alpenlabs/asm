//! Messages from the handle to the worker.

use strata_primitives::prelude::*;
use strata_service::CommandCompletionSender;
use strata_state::asm_state::AsmState;

use crate::WorkerResult;

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
