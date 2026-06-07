//! Handle for requesting proofs from the prover worker.

use strata_asm_prover_types::ProofId;
use tokio::sync::mpsc;

/// Handle for submitting proof requests to a running
/// [`ProofOrchestrator`](crate::ProofOrchestrator).
///
/// Wraps the sender side of the orchestrator's request channel. The block
/// watcher uses this to enqueue ASM/Moho proofs as new L1 blocks are processed.
/// Cloneable and cheap to pass around; dropping every clone signals the
/// orchestrator to drain and shut down.
#[derive(Debug, Clone)]
pub struct ProverWorkerHandle {
    tx: mpsc::UnboundedSender<ProofId>,
}

impl ProverWorkerHandle {
    pub(crate) fn new(tx: mpsc::UnboundedSender<ProofId>) -> Self {
        Self { tx }
    }

    /// Requests generation of the proof identified by `proof_id`.
    ///
    /// Returns the unsent request as an error if the orchestrator has shut down
    /// (its receiver was dropped).
    pub fn request_proof(&self, proof_id: ProofId) -> Result<(), mpsc::error::SendError<ProofId>> {
        self.tx.send(proof_id)
    }
}
