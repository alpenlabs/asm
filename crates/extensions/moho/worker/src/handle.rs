//! Handle for interacting with the Moho worker service.

use strata_service::ServiceMonitor;

use crate::MohoWorkerStatus;

/// Handle for observing the Moho worker service.
///
/// The worker is purely subscription-driven — it takes no commands — so the
/// handle only exposes status monitoring.
#[derive(Debug)]
pub struct MohoWorkerHandle {
    monitor: ServiceMonitor<MohoWorkerStatus>,
}

impl MohoWorkerHandle {
    pub(crate) fn new(monitor: ServiceMonitor<MohoWorkerStatus>) -> Self {
        Self { monitor }
    }

    /// Allows other services to listen to status updates.
    pub fn monitor(&self) -> &ServiceMonitor<MohoWorkerStatus> {
        &self.monitor
    }
}
