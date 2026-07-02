use std::error::Error as StdError;

use strata_identifiers::L1BlockCommitment;
use thiserror::Error;

/// Return type for Moho worker operations.
pub type MohoWorkerResult<T> = Result<T, MohoWorkerError>;

#[derive(Debug, Error)]
pub enum MohoWorkerError {
    /// The ASM anchor state the Moho state derives from was not found. The ASM
    /// worker commits the anchor state before emitting its block notification,
    /// so a miss here means the ASM and Moho stores are out of sync.
    #[error("missing ASM anchor state for block {0:?}")]
    MissingAsmState(L1BlockCommitment),

    /// The Moho state for a block was not found in the store. Hit when
    /// resolving the parent of an incoming commit: the fold chains forward from
    /// the parent's committed Moho state, so the parent must already be present.
    ///
    /// The restart gap (the Moho store trailing the ASM store after a crash) is
    /// bridged by [`sync_to_tip`](crate::sync_to_tip) on startup. Once the live
    /// subscription is running, a miss here means a genuine inconsistency the
    /// worker cannot recover from.
    #[error("missing Moho state for block {0:?}")]
    MissingMohoState(L1BlockCommitment),

    /// The parent of an L1 block commitment could not be resolved — e.g. the L1
    /// block or its header was unavailable from the provider.
    #[error("could not resolve parent of L1 block {0:?}")]
    MissingParentBlock(L1BlockCommitment),

    /// A backend the worker reads from or persists to failed. Carries the
    /// concrete backend error as a boxed [`source`](std::error::Error::source)
    /// so its full chain stays reachable. The Display string embeds the cause
    /// too, so a plain `%e`/`{}` log (which does not walk the source chain)
    /// still shows it. Boxed because the four concern traits are backed by
    /// different stores (sled, the Bitcoin client, …) with distinct error types.
    #[error("moho worker storage backend: {0}")]
    Storage(#[source] Box<dyn StdError + Send + Sync + 'static>),

    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),

    /// Launching the underlying service framework failed. The framework's
    /// `launch_async` reports `anyhow::Error`; this is the seam where that
    /// crosses into the typed surface. Carried as a
    /// [`source`](std::error::Error::source) so the anyhow chain stays reachable,
    /// and embedded in the Display string so a plain `%e`/`{}` log (which does
    /// not walk the source chain) still shows the cause. Mirrors
    /// `strata-asm-prover-worker`'s `ProverError::Other`.
    #[error("service launch: {0}")]
    ServiceLaunch(#[source] anyhow::Error),
}
