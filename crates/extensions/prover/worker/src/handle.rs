//! Handle for interacting with the prover worker service.

use strata_service::ServiceMonitor;

use crate::service::ProverStatus;

/// Handle for observing the prover worker service.
///
/// Unlike [`AsmWorkerHandle`](https://docs.rs/strata-asm-worker), the prover has
/// no command surface: it is driven entirely by the ASM worker's commit
/// subscription plus a periodic tick, so the handle exposes only the status
/// monitor. Holding it is optional — the framework keeps the service task alive
/// independently — but it is the way to observe queue depth and the last
/// committed block.
#[derive(Debug)]
pub struct ProverWorkerHandle {
    monitor: ServiceMonitor<ProverStatus>,
}

impl ProverWorkerHandle {
    /// Creates a new handle from the service monitor.
    pub(crate) fn new(monitor: ServiceMonitor<ProverStatus>) -> Self {
        Self { monitor }
    }

    /// Allows other services to listen to status updates.
    pub fn monitor(&self) -> &ServiceMonitor<ProverStatus> {
        &self.monitor
    }

    /// Returns the current status snapshot.
    pub fn status(&self) -> ProverStatus {
        self.monitor.get_current()
    }
}
