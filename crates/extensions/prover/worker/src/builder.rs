//! Builder for assembling and launching a prover worker.

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_asm_worker::Subscription;
use strata_identifiers::L1BlockCommitment;
use strata_service::{ServiceBuilder, StreamInput, TickingInput};
use strata_tasks::TaskExecutor;

use crate::{
    AsmHostLoader, AsmHostRegistry, InputBuilder, ProverContext,
    config::{OrchestratorConfig, ProverMode},
    constants,
    errors::{ProverError, ProverResult},
    handle::ProverWorkerHandle,
    service::ProverService,
    state::ProverServiceState,
};

/// Builder for assembling and launching a prover worker.
///
/// Wires the context, remote hosts, config, input builder, and the Moho worker's
/// commit subscription into a [`ProverService`] and launches it on the
/// `strata-service` async framework — mirroring how
/// [`AsmWorkerBuilder`](https://docs.rs/strata-asm-worker) launches the ASM
/// worker. The orchestration loop runs on the framework's worker task; the
/// subscription is adapted into the service input via
/// [`StreamInput`] + [`TickingInput`], so each committed [`L1BlockCommitment`]
/// becomes a `TickMsg::Msg` and the periodic wakeup a `TickMsg::Tick`.
///
/// The subscription is the *Moho* worker's commit stream, not the ASM worker's:
/// the Moho worker emits a block only after persisting its `MohoState`, so by the
/// time the prover assembles a block's proof inputs that block's `MohoState` is
/// available — the ASM → Moho → prover chain is serialized.
#[derive(Debug)]
pub struct ProverWorkerBuilder<C, L: AsmHostLoader> {
    ctx: Option<C>,
    asm_host: Option<AsmHostRegistry<L>>,
    moho_host: Option<L::Host>,
    config: Option<OrchestratorConfig>,
    input_builder: Option<InputBuilder>,
    subscription: Option<Subscription<L1BlockCommitment>>,
}

impl<C, L: AsmHostLoader> ProverWorkerBuilder<C, L> {
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

    /// Sets the ASM host registry and the fixed Moho proof host.
    pub fn with_hosts(mut self, asm_host: AsmHostRegistry<L>, moho_host: L::Host) -> Self {
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

    /// Sets the Moho worker commit subscription that drives the service.
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

impl<C, L> ProverWorkerBuilder<C, L>
where
    C: ProverContext + Send + Sync + 'static,
    L: AsmHostLoader,
{
    /// Validates the supplied dependencies, then launches the prover service and
    /// returns a handle to it.
    pub async fn launch(self, executor: &TaskExecutor) -> ProverResult<ProverWorkerHandle> {
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

        // A follower fetches proofs from the peer its config names; the RPC
        // client is derived here so callers only ever supply the config.
        let peer: Option<HttpClient> = match &config.mode {
            ProverMode::Follower(follower) => Some(
                HttpClientBuilder::default()
                    .build(&follower.peer_url)
                    .map_err(|e| ProverError::peer("failed to build peer RPC client", e))?,
            ),
            ProverMode::Generator => None,
        };

        // Capture the tick interval before `config` is moved into the state.
        let tick_interval = config.tick_interval;

        // State construction seeds the pending queue from durable state; a
        // failure fails the launch, matching the ASM worker's startup reads.
        let state =
            ProverServiceState::new(ctx, asm_host, moho_host, config, input_builder, peer).await?;

        // The Moho worker's commit subscription is a `Stream`; wrap it as a
        // service input and overlay the periodic wakeup tick.
        let input = TickingInput::new(tick_interval, StreamInput::new(subscription));

        let monitor = ServiceBuilder::<ProverService<C, L>, _>::new()
            .with_state(state)
            .with_input(input)
            .launch_async(constants::SERVICE_NAME, executor)
            .await
            .map_err(ProverError::Launch)?;

        Ok(ProverWorkerHandle::new(monitor))
    }
}

impl<C, L: AsmHostLoader> Default for ProverWorkerBuilder<C, L> {
    fn default() -> Self {
        Self::new()
    }
}
