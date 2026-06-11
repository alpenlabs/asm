//! Handle for interacting with the Moho worker service.

use strata_asm_worker::{Subscribers, Subscription};
use strata_identifiers::L1BlockCommitment;
use strata_service::ServiceMonitor;

use crate::MohoWorkerStatus;

/// Handle for observing the Moho worker service and subscribing to its commits.
///
/// The worker takes no commands, so beyond status monitoring the handle only
/// hands out [`Subscription`]s: each yields the blocks whose `MohoState` the
/// worker has durably committed, mirroring
/// [`AsmWorkerHandle::subscribe_blocks`](strata_asm_worker::AsmWorkerHandle::subscribe_blocks).
#[derive(Debug)]
pub struct MohoWorkerHandle {
    monitor: ServiceMonitor<MohoWorkerStatus>,
    subscribers: Subscribers<L1BlockCommitment>,
}

impl MohoWorkerHandle {
    /// `subscribers` is the same registry the service state emits into, so
    /// subscriptions handed out here are wired to the worker's commits.
    pub(crate) fn new(
        monitor: ServiceMonitor<MohoWorkerStatus>,
        subscribers: Subscribers<L1BlockCommitment>,
    ) -> Self {
        Self {
            monitor,
            subscribers,
        }
    }

    /// Allows other services to listen to status updates.
    pub fn monitor(&self) -> &ServiceMonitor<MohoWorkerStatus> {
        &self.monitor
    }

    /// Subscribes to per-block notifications.
    ///
    /// Returns a [`Subscription`] that yields each [`L1BlockCommitment`] the
    /// worker commits a Moho state for, starting from the next commit after this
    /// call. There is no replay: register before the worker begins processing the
    /// blocks you care about.
    pub fn subscribe_blocks(&self) -> Subscription<L1BlockCommitment> {
        self.subscribers.subscribe()
    }
}
