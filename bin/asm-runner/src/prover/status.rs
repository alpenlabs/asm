//! Observable status for the proof orchestrator.
//!
//! The orchestrator runs on its own thread behind a `LocalSet` (see
//! [`bootstrap`](mod@crate::bootstrap)), so the RPC layer cannot reach into it.
//! It publishes a snapshot through a watch channel instead: the orchestrator
//! holds the [`ProverStatusReporter`], the RPC server holds a
//! [`ProverStatusHandle`], and reads never block the tick loop.

use strata_asm_proof_types::ProverStatus;
use tokio::sync::watch;

/// Read side of the orchestrator's status snapshot.
#[derive(Clone, Debug)]
pub(crate) struct ProverStatusHandle {
    rx: watch::Receiver<Option<ProverStatus>>,
}

impl ProverStatusHandle {
    /// Returns the most recently published snapshot, or `None` before the
    /// orchestrator has finished its first tick.
    pub(crate) fn status(&self) -> Option<ProverStatus> {
        self.rx.borrow().clone()
    }
}

/// Write side, owned by the orchestrator.
#[derive(Debug)]
pub(crate) struct ProverStatusReporter {
    tx: watch::Sender<Option<ProverStatus>>,
}

impl ProverStatusReporter {
    /// Publishes a new snapshot.
    ///
    /// A watch channel with no receivers still accepts sends, so a runner
    /// configured without the proof RPC does not need special handling here.
    pub(crate) fn publish(&self, status: ProverStatus) {
        let _ = self.tx.send(Some(status));
    }
}

/// Creates a linked reporter and handle, seeded as unpublished.
///
/// The seed is `None` rather than an all-empty [`ProverStatus`]: startup
/// recovery walks the canonical chain before the first tick publishes, and
/// during that window "no proofs" and "not known yet" are very different
/// answers to give a follower measuring its lag against us.
pub(crate) fn channel() -> (ProverStatusReporter, ProverStatusHandle) {
    let (tx, rx) = watch::channel(None);
    (ProverStatusReporter { tx }, ProverStatusHandle { rx })
}
