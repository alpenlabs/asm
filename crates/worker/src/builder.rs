use strata_asm_common::AnchorState;
use strata_predicate::PredicateKey;
use strata_service::ServiceBuilder;
use strata_tasks::TaskExecutor;

use crate::{
    ExecutionRegistry, Subscribers, constants,
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
/// Receives spec-owned genesis and a registry of compiled execution targets.
#[derive(Debug)]
pub struct AsmWorkerBuilder<W> {
    context: Option<W>,
    genesis: Option<(AnchorState, PredicateKey)>,
    registry: Option<ExecutionRegistry>,
}

impl<W> AsmWorkerBuilder<W> {
    /// Create a new builder instance.
    pub fn new() -> Self {
        Self {
            context: None,
            genesis: None,
            registry: None,
        }
    }

    /// Set the worker context (implements [`WorkerContext`] trait).
    pub fn with_context(mut self, context: W) -> Self {
        self.context = Some(context);
        self
    }

    /// Supplies direct spec-owned genesis and its initial program authority.
    pub fn with_genesis(mut self, state: AnchorState, predicate: PredicateKey) -> Self {
        self.genesis = Some((state, predicate));
        self
    }

    /// Supplies supported native targets without granting activation authority.
    pub fn with_registry(mut self, registry: ExecutionRegistry) -> Self {
        self.registry = Some(registry);
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
    {
        let context = self
            .context
            .ok_or(WorkerError::MissingDependency("context"))?;
        let (genesis, predicate) = self
            .genesis
            .ok_or(WorkerError::MissingDependency("genesis"))?;
        let registry = self
            .registry
            .ok_or(WorkerError::MissingDependency("registry"))?;

        // Shared between the service state (which emits) and the handle (which
        // hands out subscriptions), so a `subscribe_blocks()` on the handle
        // registers into the same list the service fans out to.
        let subscribers = Subscribers::default();

        // Create the service state.
        let service_state =
            AsmWorkerServiceState::new(context, genesis, predicate, registry, subscribers.clone())?;

        // Create the service builder and get command handle.
        let mut service_builder =
            ServiceBuilder::<AsmWorkerService<W>, _>::new().with_state(service_state);

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

impl<W> Default for AsmWorkerBuilder<W> {
    fn default() -> Self {
        Self::new()
    }
}
