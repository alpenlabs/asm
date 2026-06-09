//! Messages from the handle to the worker.

use bitcoin::BlockHash;
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
    /// Submit an L1 block hash for ASM processing. The worker resolves its
    /// height and walks back to its last stored anchor, so one submit can drive
    /// several blocks (startup catch-up, a ZMQ gap, or a reorg). The completion
    /// sender receives the commitments actually processed, oldest first, once
    /// processing has finished.
    SubmitBlock(
        BlockHash,
        CommandCompletionSender<WorkerResult<Vec<L1BlockCommitment>>>,
    ),
}
