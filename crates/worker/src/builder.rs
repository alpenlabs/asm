use std::sync::Arc;

use strata_asm_common::AsmBootstrap;
use strata_asm_stf::AsmTargetSet;
use strata_predicate::PredicateKey;
use strata_service::ServiceBuilder;
use strata_tasks::TaskExecutor;

use crate::{
    Subscribers, constants,
    errors::{WorkerError, WorkerResult},
    handle::AsmWorkerHandle,
    service::AsmWorkerService,
    state::AsmWorkerServiceState,
    traits::WorkerContext,
};

/// Builder for constructing and launching an ASM worker service.
///
/// This encapsulates all the initialization logic and dependencies needed to
/// launch an ASM worker using the service framework, preventing impl details
/// from leaking into the caller. The builder launches the service and returns
/// a handle to it.
///
/// Generic over the worker context `W` and the target set `T` — the
/// specifications this build can execute, keyed by authorizing predicate.
#[derive(Debug)]
pub struct AsmWorkerBuilder<W, T> {
    context: Option<W>,
    targets: Option<T>,
    genesis_predicate: Option<PredicateKey>,
    bootstrap: Option<Arc<AsmBootstrap>>,
}

impl<W, T> AsmWorkerBuilder<W, T> {
    /// Create a new builder instance.
    pub fn new() -> Self {
        Self {
            context: None,
            targets: None,
            genesis_predicate: None,
            bootstrap: None,
        }
    }

    /// Set the worker context (implements [`WorkerContext`] trait).
    pub fn with_context(mut self, context: W) -> Self {
        self.context = Some(context);
        self
    }

    /// Set the specifications this build can execute.
    ///
    /// The predicate-to-specification table is a property of the release, not of
    /// a deployment; see `strata_asm_spec::StrataAsmTargets`.
    pub fn with_targets(mut self, targets: T) -> Self {
        self.targets = Some(targets);
        self
    }

    /// Set the predicate a fresh chain's genesis state hands over.
    ///
    /// Only consulted when no handover has been recorded yet — that is, on a
    /// chain being initialized. Afterwards the chain's own handovers decide.
    pub fn with_genesis_predicate(mut self, predicate: PredicateKey) -> Self {
        self.genesis_predicate = Some(predicate);
        self
    }

    /// Set the chain's validated bootstrap.
    ///
    /// The worker never sees genesis params: whoever holds them builds and
    /// validates the genesis state, and the bootstrap carries its own anchor
    /// height.
    pub fn with_bootstrap(mut self, bootstrap: Arc<AsmBootstrap>) -> Self {
        self.bootstrap = Some(bootstrap);
        self
    }

    /// Launch the ASM worker service and return a handle to it.
    ///
    /// This method validates all required dependencies, creates the service state,
    /// uses [`ServiceBuilder`] to set up the service infrastructure, and returns
    /// a handle for interacting with the worker.
    pub fn launch(self, executor: &TaskExecutor) -> WorkerResult<AsmWorkerHandle>
    where
        W: WorkerContext + Send + Sync + 'static,
        T: AsmTargetSet,
    {
        let context = self
            .context
            .ok_or(WorkerError::MissingDependency("context"))?;
        let targets = self
            .targets
            .ok_or(WorkerError::MissingDependency("targets"))?;
        let genesis_predicate = self
            .genesis_predicate
            .ok_or(WorkerError::MissingDependency("genesis predicate"))?;
        let bootstrap = self
            .bootstrap
            .ok_or(WorkerError::MissingDependency("bootstrap"))?;

        // Shared between the service state (which emits) and the handle (which
        // hands out subscriptions), so a `subscribe_blocks()` on the handle
        // registers into the same list the service fans out to.
        let subscribers = Subscribers::default();

        // Create the service state.
        let service_state = AsmWorkerServiceState::<W, T>::new(
            context,
            targets,
            genesis_predicate,
            bootstrap,
            subscribers.clone(),
        )?;

        // Create the service builder and get command handle.
        let mut service_builder =
            ServiceBuilder::<AsmWorkerService<W, T>, _>::new().with_state(service_state);

        // Create the command handle before launching.
        let command_handle = service_builder.create_command_handle(64);

        // Launch the service using the sync worker. The framework reports launch
        // failures as `anyhow`; wrap them in a typed variant at this seam.
        let service_monitor = service_builder
            .launch_sync(constants::SERVICE_NAME, executor)
            .map_err(WorkerError::ServiceLaunch)?;

        // Create and return the handle.
        let handle = AsmWorkerHandle::new(command_handle, service_monitor, subscribers);

        Ok(handle)
    }
}

impl<W, T> Default for AsmWorkerBuilder<W, T> {
    fn default() -> Self {
        Self::new()
    }
}
