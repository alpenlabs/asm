//! Subprotocol trait definition for ASM.
//!
//! This trait defines the interface every ASM subprotocol implementation must
//! provide. Each subprotocol is responsible for parsing its transactions,
//! updating its internal state, and emitting cross-protocol messages and logs.

use std::any::Any;

use ssz::{Decode, Encode};
use strata_identifiers::L1BlockCommitment;
pub use strata_l1_txfmt::SubprotocolId;

use crate::{
    AsmError, AsmLogEntry, AuxRequestCollector, HeaderVerificationState, SectionState, StfParams,
    TxInputRef, VerifiedAuxData, msg::InterprotoMsg,
};

/// Context for [`Subprotocol::pre_process_txs`].
///
/// Aux-data requests declared here MUST be gated on exactly the same fork
/// conditions as the [`Subprotocol::process_txs`] phase that later consumes
/// them, otherwise aux data is requested but never consumed — or consumed but
/// never requested, failing at runtime.
#[derive(Debug)]
pub struct PreProcessTxsCtx<'a> {
    /// Height of the L1 block whose transactions are being pre-processed.
    ///
    /// Needed to evaluate fork gates: pre-processing runs against the
    /// *previous* block's state and, unlike `process_txs`, receives no
    /// [`HeaderVerificationState`] to read the height from, so it is not
    /// otherwise derivable in this phase.
    pub target_height: u64,

    /// STF params the transition executes under.
    ///
    /// Needed for the fork schedule that gates aux requests, evaluated
    /// against [`Self::target_height`].
    pub stf_params: &'a StfParams,
}

/// Context for [`Subprotocol::process_txs`].
#[derive(Debug)]
pub struct ProcessTxsCtx<'a> {
    /// Verification state of the L1 block being processed.
    ///
    /// Needed as the source of the block commitment — its height drives fork
    /// gates and height-based logic (e.g. assignment expiry), and it carries
    /// PoW data such as the accumulated work.
    pub header_vs: &'a HeaderVerificationState,

    /// Aux data requested during [`Subprotocol::pre_process_txs`], verified
    /// against the anchor state.
    ///
    /// Needed so processing can consume the external data (manifest hashes,
    /// proofs, ...) it declared a dependency on during pre-processing.
    pub verified_aux_data: &'a VerifiedAuxData,

    /// STF params the transition executes under.
    ///
    /// Needed for the fork schedule that gates processing logic, evaluated
    /// against the height of `header_vs.last_verified_block`.
    pub stf_params: &'a StfParams,
}

/// Context for [`Subprotocol::process_msgs`].
#[derive(Debug)]
pub struct ProcessMsgsCtx<'a> {
    /// Commitment of the L1 block being processed.
    ///
    /// Needed to anchor message effects to the block (e.g. withdrawal
    /// assignments record the L1 block they were created at).
    pub l1ref: &'a L1BlockCommitment,

    /// STF params the transition executes under.
    ///
    /// Needed so message handling can be fork-gated on the same conditions as
    /// the tx-processing phase that produced the messages.
    pub stf_params: &'a StfParams,
}

/// Trait for defining subprotocol behavior within the ASM framework.
///
/// Subprotocols are modular components that can be plugged into the ASM to handle
/// specific transaction types and maintain their own state within the anchor state.
/// Each subprotocol defines its own transaction processing logic, message handling,
/// and state management.
///
/// The ASM filters SPS-50 transactions by subprotocol ID and passes only the relevant
/// transactions to each subprotocol. Each subprotocol does the following, in order:
///
/// 1. processes its transactions to update its own state, create inter-protocol messages to be
///    consumed by other subprotocols, and emit logs,
/// 2. receives incoming inter-protocol messages from other subprotocols to finalize and serialize
///    its state for inclusion in the global AnchorState.
///
/// The ASM design assumes subprotocols are not adversarial against each other, so no additional
/// validation is performed on incoming messages.
///
/// # Example
///
/// ```ignore
/// struct MySubprotocol;
///
/// impl Subprotocol for MySubprotocol {
///     const ID: SubprotocolId = 42;
///     type State = MyState;
///     type InitConfig = MyInitConfig;
///     type Msg = MyMessage;
///
///     fn init(config: &Self::InitConfig) -> Self::State {
///        // init logic
///     }
///
///     fn pre_process_txs(
///         state: &Self::State,
///         txs: &[TxInputRef],
///         collector: &mut AuxRequestCollector,
///         ctx: &PreProcessTxsCtx<'_>,
///     ) {
///         // Pre-process transactions and request auxiliary data
///     }
///
///     fn process_txs(
///         state: &mut Self::State,
///         txs: &[TxInputRef],
///         relayer: &mut impl MsgRelayer,
///         ctx: &ProcessTxsCtx<'_>,
///     ) {
///         // Process transactions
///     }
///
///     fn process_msgs(state: &mut Self::State, msgs: &[Self::Msg], ctx: &ProcessMsgsCtx<'_>) {
///         // Process messages
///     }
/// }
/// ```
pub trait Subprotocol: 'static {
    /// The subprotocol ID used when searching for relevant transactions.
    const ID: SubprotocolId;

    /// Configuration used to initialize the subprotocol's state.
    ///
    /// `Any` so genesis construction can locate a subprotocol's config in a
    /// heterogeneous params list by its type.
    type InitConfig: Any;

    /// State type serialized into the ASM state structure.
    type State: Any + Decode + Encode;

    /// Message type that we receive messages from other subprotocols using.
    type Msg: Clone + InterprotoMsg + Any;

    /// Constructs a new state using the provided initialization configuration.
    ///
    /// # Arguments
    /// * `config` - The subprotocol's initialization configuration, from which we derive an initial
    ///   state to use when the pre-state does not contain an instance.
    ///
    /// # Returns
    ///
    /// The initialized state
    fn init(config: &Self::InitConfig) -> Self::State;

    /// Pre-processes a batch of L1 transactions by registering any required auxiliary data.
    ///
    /// During this phase, the subprotocol declares *external* data it will need before actual
    /// processing. Any required L1 headers, block-metadata, or other off-chain data should be
    /// requested via the `AuxRequestCollector`.
    /// (e.g., Merkle proof for logs emitted in a previous block from "history_mmr" in AnchorState)
    ///
    /// This method is called before transaction processing to allow subprotocols to specify
    /// any auxiliary data they need (such as L1 block headers, Merkle proofs, or other metadata).
    /// The requested data will be made available during the subsequent `process_txs` call.
    ///
    /// # Arguments
    /// * `state` - Current state of the subprotocol
    /// * `txs` - Slice of L1 transactions relevant to this subprotocol
    /// * `collector` - Interface for registering auxiliary input requirements
    /// * `ctx` - Ambient context; see [`PreProcessTxsCtx`] for the fork-gating invariant
    fn pre_process_txs(
        _state: &Self::State,
        _txs: &[TxInputRef<'_>],
        _collector: &mut AuxRequestCollector,
        _ctx: &PreProcessTxsCtx<'_>,
    ) {
        // default nothing
    }

    /// Processes a batch of L1 transactions, extracting all relevant information for this
    /// subprotocol.
    ///
    /// This is the core transaction processing method where subprotocols implement their
    /// specific business logic. The method receives auxiliary data (requested
    /// during `pre_process_txs`) and can generate messages to other subprotocols and emit logs.
    ///
    /// # Arguments
    /// * `state` - Mutable reference to the subprotocol's state
    /// * `txs` - Slice of L1 transactions relevant to this subprotocol
    /// * `relayer` - Interface for sending messages to other subprotocols and emitting logs
    /// * `ctx` - Ambient context; see [`ProcessTxsCtx`] for what each field provides
    fn process_txs(
        state: &mut Self::State,
        txs: &[TxInputRef<'_>],
        relayer: &mut impl MsgRelayer,
        ctx: &ProcessTxsCtx<'_>,
    );

    /// Processes messages received from other subprotocols.
    ///
    /// This method handles inter-subprotocol communication, allowing subprotocols to
    /// react to events and data from other components in the ASM.
    ///
    /// # Arguments
    /// * `state` - Mutable reference to the subprotocol's state
    /// * `msgs` - Slice of messages received from other subprotocols
    /// * `ctx` - Ambient context; see [`ProcessMsgsCtx`] for what each field provides
    ///
    /// TODO(STR-3028): Enable log emission from process_msgs to support multi-round
    /// inter-subprotocol messaging
    fn process_msgs(state: &mut Self::State, msgs: &[Self::Msg], ctx: &ProcessMsgsCtx<'_>);
}

/// Generic message relayer interface which subprotocols can use to interact
/// with each other and the outside world.
pub trait MsgRelayer: Any {
    /// Relays a message to the destination subprotocol.
    fn relay_msg(&mut self, m: &dyn InterprotoMsg);

    /// Emits an output log message.
    fn emit_log(&mut self, log: AsmLogEntry);

    /// Gets this msg relayer as a `&dyn Any`.
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

/// Subprotocol handler trait for a loaded subprotocol.
pub trait SubprotoHandler {
    /// Gets the ID of the subprotocol.  This should just directly expose it
    /// as-is.
    fn id(&self) -> SubprotocolId;

    /// Pre-processes a batch of L1 transactions by delegating to the inner
    /// subprotocol's `pre_process_txs` implementation.
    ///
    /// Any required auxiliary data should be registered via the provided `AuxRequestCollector` for
    /// the subsequent processing phase.
    fn pre_process_txs(
        &mut self,
        txs: &[TxInputRef<'_>],
        collector: &mut AuxRequestCollector,
        ctx: &PreProcessTxsCtx<'_>,
    );

    /// Processes a batch of L1 transactions by delegating to the underlying subprotocol's
    /// `process_txs` implementation.
    ///
    /// Messages and logs generated by the subprotocol will be sent via the provided `MsgRelayer`.
    fn process_txs(
        &mut self,
        txs: &[TxInputRef<'_>],
        relayer: &mut dyn MsgRelayer,
        ctx: &ProcessTxsCtx<'_>,
    );

    /// Accepts a message.  This is called while processing other subprotocols.
    /// These should not be processed until we do the finalization.
    ///
    /// This MUST NOT act on any messages that were accepted before this was
    /// called.
    ///
    /// # Panics
    ///
    /// If an mismatched message type (behind the `dyn`) is provided.
    fn accept_msg(&mut self, msg: &dyn InterprotoMsg);

    /// Processes the buffered messages stored in the handler.
    fn process_buffered_msgs(&mut self, ctx: &ProcessMsgsCtx<'_>);

    /// Repacks the state into a [`SectionState`] instance.
    ///
    /// Returns [`AsmError::SectionTooLarge`] if the serialised state exceeds
    /// the SSZ section-data capacity.
    fn to_section(&self) -> Result<SectionState, AsmError>;
}
