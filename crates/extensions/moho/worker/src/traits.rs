//! Storage traits the Moho worker interfaces through.
//!
//! The worker derives each [`MohoState`] from the ASM anchor state the ASM
//! worker already committed, then persists it. Those two concerns are split
//! into separate traits so an implementor can back them with whatever subsystem
//! it likes:
//!
//! - [`AsmStateProvider`] — reads the [`AnchorState`] and [`AsmLogEntry`]s the Moho state is
//!   computed from.
//! - [`MohoStateStore`] — persists and loads the derived [`MohoState`].
//!
//! [`MohoWorkerContext`] is the umbrella with a blanket impl, mirroring
//! `strata-asm-worker`'s [`WorkerContext`](strata_asm_worker::WorkerContext):
//! implement the two concern traits and get the context for free.

use moho_types::MohoState;
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_identifiers::L1BlockCommitment;

use crate::MohoWorkerResult;

/// Reads the ASM anchor states and logs the Moho worker derives from.
pub trait AsmStateProvider {
    /// Fetches the [`AnchorState`] committed by the ASM worker for `blockid`.
    ///
    /// Errors with [`MissingAsmState`](crate::MohoWorkerError::MissingAsmState)
    /// when no anchor state exists for the block.
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<AnchorState>;

    /// Fetches the [`AsmLogEntry`]s the ASM worker emitted for `blockid`.
    ///
    /// Committed alongside the anchor state, so this errors with
    /// [`MissingAsmState`](crate::MohoWorkerError::MissingAsmState) when the
    /// block's ASM commit is absent. An empty vec means the block had no logs.
    fn get_anchor_logs(&self, blockid: &L1BlockCommitment) -> MohoWorkerResult<Vec<AsmLogEntry>>;
}

/// Persists and loads the derived per-block [`MohoState`].
pub trait MohoStateStore {
    /// Fetches the most recently committed [`MohoState`] and the block it is
    /// anchored to, or `None` if the store is empty. Used to resume the
    /// forward-only fold across restarts.
    fn get_latest_moho_state(&self) -> MohoWorkerResult<Option<(L1BlockCommitment, MohoState)>>;

    /// Persists the [`MohoState`] derived for `blockid`.
    fn store_moho_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &MohoState,
    ) -> MohoWorkerResult<()>;
}

/// Context the Moho worker interacts with the outside world through.
///
/// Umbrella over [`AsmStateProvider`] and [`MohoStateStore`]. The blanket impl
/// means any type implementing both automatically implements
/// `MohoWorkerContext`, so implementors never name it directly.
pub trait MohoWorkerContext: AsmStateProvider + MohoStateStore {}

impl<T> MohoWorkerContext for T where T: AsmStateProvider + MohoStateStore {}
