//! Builder for assembling a prover worker.

use strata_asm_worker::Subscription;
use strata_identifiers::L1BlockCommitment;
use zkaleido::ZkVmRemoteHost;

use crate::{
    InputBuilder, ProofOrchestrator, ProverContext,
    config::OrchestratorConfig,
    errors::{ProverError, ProverResult},
};

/// Builder for assembling a prover worker.
///
/// Wires the context, remote hosts, config, input builder, and the ASM worker's
/// commit subscription into a [`ProofOrchestrator`]. The orchestrator's only
/// input is that subscription: it turns each committed [`L1BlockCommitment`]
/// into the proofs the block requires.
///
/// The orchestrator is *not* spawned here: its run loop is `!Send` (the
/// upstream `ZkVmRemoteProver` is `#[async_trait(?Send)]`), so the caller must
/// drive [`ProofOrchestrator::run`] itself — typically on a dedicated thread
/// with a single-threaded runtime and a `LocalSet`.
#[derive(Debug)]
pub struct ProverWorkerBuilder<C, H> {
    ctx: Option<C>,
    asm_host: Option<H>,
    moho_host: Option<H>,
    config: Option<OrchestratorConfig>,
    input_builder: Option<InputBuilder>,
    subscription: Option<Subscription<L1BlockCommitment>>,
}

impl<C, H> ProverWorkerBuilder<C, H> {
    /// Creates a new, empty builder.
    pub fn new() -> Self {
        Self {
            ctx: None,
            asm_host: None,
            moho_host: None,
            config: None,
            input_builder: None,
            subscription: None,
        }
    }

    /// Sets the prover context (implements [`ProverContext`]).
    pub fn with_context(mut self, ctx: C) -> Self {
        self.ctx = Some(ctx);
        self
    }

    /// Sets the `(asm, moho)` remote host pair.
    pub fn with_hosts(mut self, asm_host: H, moho_host: H) -> Self {
        self.asm_host = Some(asm_host);
        self.moho_host = Some(moho_host);
        self
    }

    /// Sets the orchestrator configuration.
    pub fn with_config(mut self, config: OrchestratorConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the input builder used to assemble ZkVM inputs.
    pub fn with_input_builder(mut self, input_builder: InputBuilder) -> Self {
        self.input_builder = Some(input_builder);
        self
    }

    /// Sets the ASM worker commit subscription that drives the orchestrator.
    ///
    /// Subscribe *before* the worker starts processing blocks — there is no
    /// replay buffer, so any block committed before this subscription exists is
    /// not seen.
    pub fn with_block_subscription(
        mut self,
        subscription: Subscription<L1BlockCommitment>,
    ) -> Self {
        self.subscription = Some(subscription);
        self
    }
}

impl<C: ProverContext, H: ZkVmRemoteHost> ProverWorkerBuilder<C, H> {
    /// Validates the supplied dependencies and assembles the orchestrator for
    /// the caller to drive.
    pub fn build(self) -> ProverResult<ProofOrchestrator<C, H>> {
        let ctx = self.ctx.ok_or(ProverError::MissingDependency("context"))?;
        let asm_host = self
            .asm_host
            .ok_or(ProverError::MissingDependency("asm_host"))?;
        let moho_host = self
            .moho_host
            .ok_or(ProverError::MissingDependency("moho_host"))?;
        let config = self
            .config
            .ok_or(ProverError::MissingDependency("config"))?;
        let input_builder = self
            .input_builder
            .ok_or(ProverError::MissingDependency("input_builder"))?;
        let subscription = self
            .subscription
            .ok_or(ProverError::MissingDependency("subscription"))?;

        Ok(ProofOrchestrator::new(
            ctx,
            asm_host,
            moho_host,
            config,
            input_builder,
            subscription,
        ))
    }
}

impl<C, H> Default for ProverWorkerBuilder<C, H> {
    fn default() -> Self {
        Self::new()
    }
}
