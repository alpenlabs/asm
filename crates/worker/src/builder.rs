use strata_asm_common::AsmSpec;
use strata_service::ServiceBuilder;
use strata_tasks::TaskExecutor;

use crate::{
    constants, errors::WorkerError, handle::AsmWorkerHandle, service::AsmWorkerService,
    state::AsmWorkerServiceState, traits::WorkerContext,
};

/// Builder for constructing and launching an ASM worker service.
///
/// This encapsulates all the initialization logic and dependencies needed to
/// launch an ASM worker using the service framework, preventing impl details
/// from leaking into the caller. The builder launches the service and returns
/// a handle to it.
///
/// Generic over the worker context `W` and the ASM spec `S`, so callers can
/// inject alternative specs (e.g. a debug-wrapped spec for testing) without
/// forking the worker.
#[derive(Debug)]
pub struct AsmWorkerBuilder<W, S: AsmSpec> {
    context: Option<W>,
    params: Option<S::Params>,
    spec: Option<S>,
}

impl<W, S: AsmSpec> AsmWorkerBuilder<W, S> {
    /// Create a new builder instance.
    pub fn new() -> Self {
        Self {
            context: None,
            params: None,
            spec: None,
        }
    }

    /// Set the worker context (implements [`WorkerContext`] trait).
    pub fn with_context(mut self, context: W) -> Self {
        self.context = Some(context);
        self
    }

    /// Set the ASM parameters used to construct the genesis state.
    pub fn with_params(mut self, params: S::Params) -> Self {
        self.params = Some(params);
        self
    }

    /// Set the ASM spec driving the subprotocol pipeline.
    ///
    /// Production deployments pass [`strata_asm_spec::StrataAsmSpec`]; tests
    /// can pass a wrapped debug spec to inject extra subprotocols.
    pub fn with_asm_spec(mut self, spec: S) -> Self {
        self.spec = Some(spec);
        self
    }

    /// Launch the ASM worker service and return a handle to it.
    ///
    /// This method validates all required dependencies, creates the service state,
    /// uses [`ServiceBuilder`] to set up the service infrastructure, and returns
    /// a handle for interacting with the worker.
    pub fn launch(self, executor: &TaskExecutor) -> anyhow::Result<AsmWorkerHandle>
    where
        W: WorkerContext + Send + Sync + 'static,
        S: AsmSpec + Send + Sync + 'static,
        S::Params: Send + Sync + 'static,
    {
        let context = self
            .context
            .ok_or(WorkerError::MissingDependency("context"))?;
        let params = self
            .params
            .ok_or(WorkerError::MissingDependency("params"))?;
        let spec = self.spec.ok_or(WorkerError::MissingDependency("spec"))?;

        // Create the service state.
        let service_state = AsmWorkerServiceState::new(context, spec, params);

        // Create the service builder and get command handle.
        let mut service_builder =
            ServiceBuilder::<AsmWorkerService<W, S>, _>::new().with_state(service_state);

        // Create the command handle before launching.
        let command_handle = service_builder.create_command_handle(64);

        // Launch the service using the sync worker.
        let service_monitor = service_builder.launch_sync(constants::SERVICE_NAME, executor)?;

        // Create and return the handle.
        let handle = AsmWorkerHandle::new(command_handle, service_monitor);

        Ok(handle)
    }
}

impl<W, S: AsmSpec> Default for AsmWorkerBuilder<W, S> {
    fn default() -> Self {
        Self::new()
    }
}
