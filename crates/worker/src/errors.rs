use bitcoin::Network;
use strata_asm_common::{AsmError, AsmSpecId};
use strata_btc_types::BitcoinTxid;
use strata_identifiers::{L1BlockCommitment, L1BlockId, L1Height};
use strata_service::ServiceError;
use thiserror::Error;

/// Return type for worker messages.
pub type WorkerResult<T> = Result<T, WorkerError>;

/// The specific way a configured anchor disagrees with the L1 chain.
///
/// Produced at startup by the worker's anchor validation and wrapped by
/// [`WorkerError::AnchorMismatch`]. Each variant carries both the value the
/// anchor declared and the value the L1 source reports.
#[derive(Debug, Error)]
pub enum AnchorMismatch {
    /// The anchor's network differs from the backing L1 source.
    #[error("network: anchor declares {anchor:?}, L1 source reports {l1:?}")]
    Network { anchor: Network, l1: Network },

    /// The anchor commits to a different block than the one at its height on
    /// the active chain.
    #[error("block at height {height}: anchor commits to {anchor:?}, L1 has {l1:?}")]
    Block {
        height: u64,
        anchor: L1BlockId,
        l1: L1BlockId,
    },

    /// The anchor's epoch-start timestamp differs from the timestamp of the
    /// first block of its current difficulty-adjustment epoch.
    #[error(
        "epoch start timestamp: anchor declares {anchor}, L1 epoch start (height {epoch_start_height}) is {l1}"
    )]
    EpochStartTimestamp {
        epoch_start_height: u64,
        anchor: u32,
        l1: u32,
    },

    /// The anchor's next-block target differs from the target the anchor's
    /// successor is required to satisfy.
    #[error("next target: anchor declares {anchor}, L1 requires {l1}")]
    NextTarget { anchor: u32, l1: u32 },
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("ASM error: {0}")]
    AsmError(#[from] strata_asm_common::AsmError),

    #[error("missing genesis ASM state.")]
    MissingGenesisState,

    /// The anchor configured in `params` does not match the actual L1 chain.
    /// Surfaced at startup so a misconfigured anchor fails fast instead of one
    /// L1 block later, when header verification rejects the anchor's successor.
    #[error("configured anchor is inconsistent with the L1 chain: {0}")]
    AnchorMismatch(#[from] AnchorMismatch),

    #[error("missing l1 block {0:?}")]
    MissingL1Block(L1BlockId),

    #[error("missing ASM state for the block {0:?}")]
    MissingAsmState(L1BlockId),

    #[error("missing aux data for the block {0:?}")]
    MissingAuxData(L1BlockCommitment),

    /// A Bitcoin RPC call failed after exhausting its retry budget.
    ///
    /// Carries the underlying error as a `#[source]` so `Error::source()` chains
    /// all the way down to the concrete RPC error (e.g. `ClientError`), which
    /// stays recoverable via `downcast_ref`. The worker is generic over its
    /// `WorkerContext`, so it deliberately does not name the concrete RPC client
    /// type here; the context impl attaches call context (which call, which
    /// block) before wrapping.
    #[error("btc rpc: {0}")]
    BtcRpc(#[source] anyhow::Error),

    /// A backing store operation failed. Carries the underlying storage error as
    /// a `#[source]` so its full chain is preserved rather than bucketed into an
    /// opaque marker.
    #[error("db error: {0}")]
    DbError(#[source] anyhow::Error),

    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),

    #[error("not yet implemented")]
    Unimplemented,

    // Auxiliary data resolution errors
    #[error("Bitcoin transaction not found: {0:?}")]
    BitcoinTxNotFound(BitcoinTxid),

    #[error("L1 block not found at height {height}")]
    L1BlockNotFound { height: L1Height },

    /// The L1 source reported a height that does not fit [`L1Height`].
    #[error("L1 height {height} does not fit in a block commitment")]
    HeightOutOfRange { height: u64 },

    #[error("No ASM state available")]
    NoAsmState,

    #[error("Invalid manifest hash range: start={start}, end={end}")]
    InvalidManifestRange { start: u64, end: u64 },

    #[error("Invalid L1 height range: start={start}, end={end}")]
    InvalidHeightRange { start: u64, end: u64 },

    #[error("Manifest hash not found for MMR index {index}")]
    ManifestHashNotFound { index: u64 },

    #[error("MMR proof generation failed for index {index}")]
    MmrProofFailed { index: u64 },

    #[error("Manifest hash out of bound (max {max}, requested {index})")]
    ManifestIndexOutOfBound { index: u64, max: u64 },

    #[error("ASM worker exited unexpectedly")]
    WorkerExited,

    /// A service-framework operation failed for a reason other than the worker
    /// having exited (a cancelled wait, a panicked blocking thread, an unknown
    /// input). Carries the concrete [`ServiceError`] as a `#[source]` so the
    /// exact framework cause is preserved rather than flattened to a string.
    #[error("service framework error: {0}")]
    Service(#[source] ServiceError),

    /// Launching the worker through the service framework failed. The framework
    /// reports these as open-ended `anyhow` errors (thread spawn, runtime
    /// wiring), so carry the cause verbatim rather than bucketing it.
    #[error("failed to launch worker service: {0}")]
    ServiceLaunch(#[source] anyhow::Error),

    /// The parent's handover authorizes rules this build cannot execute.
    ///
    /// The chain has enacted an ASM verifying-key upgrade whose predicate this
    /// binary has no specification for. Continuing under the rules it does have
    /// would produce state no proof can ever be made for, so the worker stops
    /// here; a restart with a build that carries the rules resumes from the same
    /// block, because nothing was committed.
    #[error(
        "no ASM specification in this build executes predicate {predicate}, handed over by {block}"
    )]
    UnsupportedPredicate {
        /// Rendering of the predicate the parent handed over.
        predicate: String,
        /// The block whose handover selected it.
        block: strata_identifiers::L1BlockCommitment,
    },

    /// A committed block has no recorded handover.
    ///
    /// The handover is written before the block's anchor state commits, so a
    /// committed anchor without one means the store lost data rather than that
    /// the worker raced itself.
    #[error("no ASM predicate handover recorded for committed block {block}")]
    MissingHandover {
        /// The block whose handover is absent.
        block: strata_identifiers::L1BlockCommitment,
    },

    /// A stored anchor selected for startup or reorg adoption is not executable
    /// under the target its persisted handover selects.
    #[error(
        "stored anchor {block} is not executable under ASM spec {target} selected by predicate {predicate}: {source}"
    )]
    InvalidStoredAnchor {
        /// Stored or bootstrap anchor being adopted.
        block: L1BlockCommitment,
        /// Target selected for the anchor's child.
        target: AsmSpecId,
        /// Rendering of the selecting predicate for operator diagnosis.
        predicate: String,
        /// Structural, schema, payload, or migration-preflight failure.
        #[source]
        source: Box<AsmError>,
    },

    /// The state is not canonical output of the specification its parent
    /// handover says executed the anchor block.
    #[error(
        "stored anchor {block} is not canonical output of ASM spec {producer} authorized by parent {parent} with predicate {predicate}: {source}"
    )]
    InvalidStoredProducerState {
        /// Stored anchor being considered for adoption.
        block: L1BlockCommitment,
        /// Parent whose handover authorized the anchor block.
        parent: L1BlockCommitment,
        /// Specification that executed the anchor block.
        producer: AsmSpecId,
        /// Rendering of the producer predicate for diagnosis.
        predicate: String,
        /// Schema, payload, or migration-classification failure.
        #[source]
        source: Box<AsmError>,
    },

    /// State accepted only as migration input under the specification that was
    /// supposed to have already executed the anchor block.
    ///
    /// A producer migrates before executing and always emits its own target
    /// schema. Seeing its predecessor schema here means the state could not have
    /// been produced by the parent-authorized rules.
    #[error(
        "stored anchor {block} has predecessor ASM spec {state_spec} state, but parent {parent} authorized producer ASM spec {producer}"
    )]
    StoredAnchorNotProducerOutput {
        /// Stored anchor being considered for adoption.
        block: L1BlockCommitment,
        /// Parent whose handover authorized the anchor block.
        parent: L1BlockCommitment,
        /// Specification that executed the anchor block.
        producer: AsmSpecId,
        /// Schema in which the stored state was classified.
        state_spec: AsmSpecId,
    },

    /// The anchor hands over to a different target that does not declare its
    /// producer as the direct predecessor.
    #[error(
        "stored anchor {block} cannot hand over from producer ASM spec {producer} to target ASM spec {target}: target declares predecessor {declared_predecessor:?}"
    )]
    InvalidStoredTargetSuccession {
        /// Stored anchor whose next handover is being checked.
        block: L1BlockCommitment,
        /// Specification that produced the anchor state.
        producer: AsmSpecId,
        /// Specification selected for the anchor's child.
        target: AsmSpecId,
        /// Target's declared direct predecessor, if any.
        declared_predecessor: Option<AsmSpecId>,
    },

    /// The bootstrap was validated under one specification while the genesis
    /// predicate selects another. Equal schemas are not enough here: genesis
    /// values can have different semantics even when their layouts coincide.
    #[error(
        "bootstrap anchor {block} was built for ASM spec {bootstrap}, but its genesis predicate selects spec {target}"
    )]
    BootstrapTargetMismatch {
        /// Configured bootstrap anchor.
        block: L1BlockCommitment,
        /// Specification used to construct and validate the bootstrap.
        bootstrap: AsmSpecId,
        /// Specification selected by the genesis predicate.
        target: AsmSpecId,
    },

    /// A stored row was selected by one block commitment but its decoded state
    /// claims to have processed another block.
    #[error("stored ASM anchor selected as {expected} contains state for {actual}")]
    StoredAnchorCommitmentMismatch {
        /// Commitment selected by the active-tip record or explicit lookup.
        expected: L1BlockCommitment,
        /// Commitment embedded in the decoded anchor state.
        actual: L1BlockCommitment,
    },

    /// The durable state at or below the configured bootstrap boundary is not
    /// the exact validated bootstrap state.
    ///
    /// No ASM transition runs at the bootstrap height, so there is no legitimate
    /// alternate state at that boundary. Accepting one would let a different
    /// magic, genesis subprotocol values, or history accumulator redefine the
    /// chain while retaining the same L1 anchor.
    #[error(
        "stored ASM anchor {actual} at or below bootstrap {bootstrap} differs from the validated bootstrap state"
    )]
    StoredBootstrapMismatch {
        /// Configured and independently validated bootstrap commitment.
        bootstrap: L1BlockCommitment,
        /// Commitment selected by the durable active-tip record.
        actual: L1BlockCommitment,
    },

    /// A persisted handover at the bootstrap anchor differs from the configured
    /// genesis predicate.
    ///
    /// The bootstrap block did not execute the ASM and therefore cannot enact a
    /// predicate rotation. Even another predicate mapped to the same semantic
    /// spec is not an authorized substitute for the chain's genesis predicate.
    #[error(
        "bootstrap anchor {block} has persisted predicate {actual}, expected configured genesis predicate {expected}"
    )]
    BootstrapHandoverMismatch {
        /// Bootstrap commitment whose handover was read.
        block: L1BlockCommitment,
        /// Configured genesis predicate.
        expected: String,
        /// Predicate persisted under the bootstrap commitment.
        actual: String,
    },

    /// A bootstrap-height anchor cannot be a migration input: no prior ASM
    /// block exists in this chain whose handover could authorize its schema.
    #[error(
        "startup anchor {block} has predecessor ASM spec {predecessor} state for target {target}, but it is not above the bootstrap boundary"
    )]
    PredecessorStateAtBootstrap {
        /// Anchor incorrectly presented as an activation boundary.
        block: L1BlockCommitment,
        /// Selected successor target.
        target: AsmSpecId,
        /// Direct predecessor whose schema the anchor carries.
        predecessor: AsmSpecId,
    },

    /// The stored state looks like the target's direct predecessor, but the
    /// parent handover proves that another specification produced it.
    #[error(
        "startup anchor {block} cannot migrate into ASM spec {target}: parent {parent} authorized spec {actual}, expected direct predecessor {expected}"
    )]
    InvalidPredecessorBoundary {
        /// Stored anchor being validated.
        block: L1BlockCommitment,
        /// Parent whose handover authorized `block`.
        parent: L1BlockCommitment,
        /// Target selected for the next block.
        target: AsmSpecId,
        /// Direct predecessor declared by the target.
        expected: AsmSpecId,
        /// Specification the parent handover actually authorized.
        actual: AsmSpecId,
    },
}
