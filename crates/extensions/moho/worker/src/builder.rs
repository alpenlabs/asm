//! Builder for constructing and launching the Moho worker service.

use strata_asm_worker::{Subscribers, Subscription};
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;
use strata_service::{ServiceBuilder, StreamInput};
use strata_tasks::TaskExecutor;

use crate::{
    MohoWorkerContext, MohoWorkerHandle, constants,
    errors::MohoWorkerError,
    service::{self, MohoWorkerService},
    state::MohoWorkerServiceState,
};

/// Builder for launching a Moho worker driven by the ASM worker's per-block
/// subscription.
///
/// Wire it with the storage context, the subscription handed out by
/// [`AsmWorkerHandle::subscribe_blocks`](strata_asm_worker::AsmWorkerHandle::subscribe_blocks),
/// the genesis block, and the ASM predicate that seeds the genesis Moho state.
///
/// Subscribe *before* the ASM worker begins committing blocks: the subscription
/// has no replay, so the worker must be wired in while the stream still starts
/// at the genesis successor.
#[derive(Debug)]
pub struct MohoWorkerBuilder<W> {
    context: Option<W>,
    subscription: Option<Subscription<L1BlockCommitment>>,
    genesis_block: Option<L1BlockCommitment>,
    asm_predicate: Option<PredicateKey>,
}

impl<W> MohoWorkerBuilder<W> {
    /// Create a new builder instance.
    pub fn new() -> Self {
        Self {
            context: None,
            subscription: None,
            genesis_block: None,
            asm_predicate: None,
        }
    }

    /// Set the storage context (implements [`MohoWorkerContext`]).
    pub fn with_context(mut self, context: W) -> Self {
        self.context = Some(context);
        self
    }

    /// Set the ASM commit subscription driving the worker.
    pub fn with_subscription(mut self, subscription: Subscription<L1BlockCommitment>) -> Self {
        self.subscription = Some(subscription);
        self
    }

    /// Set the genesis block whose ASM anchor state seeds the genesis Moho state.
    pub fn with_genesis_block(mut self, genesis_block: L1BlockCommitment) -> Self {
        self.genesis_block = Some(genesis_block);
        self
    }

    /// Set the ASM predicate carried by the genesis Moho state.
    pub fn with_asm_predicate(mut self, asm_predicate: PredicateKey) -> Self {
        self.asm_predicate = Some(asm_predicate);
        self
    }

    /// Launch the Moho worker service and return a handle to it.
    ///
    /// Validates dependencies, seeds or resumes the service state, adapts the
    /// subscription into a stream input, and spawns the async worker.
    pub async fn launch(self, executor: &TaskExecutor) -> anyhow::Result<MohoWorkerHandle>
    where
        W: MohoWorkerContext + Send + Sync + 'static,
    {
        let context = self
            .context
            .ok_or(MohoWorkerError::MissingDependency("context"))?;
        let subscription = self
            .subscription
            .ok_or(MohoWorkerError::MissingDependency("subscription"))?;
        let genesis_block = self
            .genesis_block
            .ok_or(MohoWorkerError::MissingDependency("genesis_block"))?;
        let asm_predicate = self
            .asm_predicate
            .ok_or(MohoWorkerError::MissingDependency("asm_predicate"))?;

        // Shared between the service state (which emits each committed block)
        // and the handle (which hands out subscriptions), so a downstream
        // `subscribe_blocks()` registers into the same list the service fans out
        // to. Mirrors the ASM worker's builder.
        let subscribers = Subscribers::default();

        // Seed or resume synchronously before launch, mirroring the ASM worker:
        // the genesis Moho state must exist before the first commit is folded.
        let mut state = MohoWorkerServiceState::new(
            context,
            genesis_block,
            asm_predicate,
            subscribers.clone(),
        )?;

        // Catch up to the ASM tip before the subscription takes over: on restart
        // the Moho store can trail the ASM store, and the stream has no replay to
        // bridge the gap. This catch-up does not emit (no subscriber is attached
        // yet), matching the no-replay semantics of the ASM commit stream.
        service::sync_to_tip(&mut state)?;

        let input = StreamInput::new(subscription);
        let monitor = ServiceBuilder::<MohoWorkerService<W>, _>::new()
            .with_state(state)
            .with_input(input)
            .launch_async(constants::SERVICE_NAME, executor)
            .await?;

        Ok(MohoWorkerHandle::new(monitor, subscribers))
    }
}

impl<W> Default for MohoWorkerBuilder<W> {
    fn default() -> Self {
        Self::new()
    }
}
