//! Which operator-claim version the subprotocol commits as its export leaf.
//!
//! The leaf hash is consensus state, so the choice belongs to the subprotocol version rather
//! than to state or params. [`BridgeSubproto`](crate::BridgeSubproto) carries the selection as a
//! type parameter, which keeps one [`Subprotocol`](strata_asm_common::Subprotocol)
//! implementation covering every released version instead of one copy per claim shape.
//!
//! This parameterizes the claim axis only. A change to the bridge section schema is a different
//! kind of change: it moves `STATE_VERSION`, needs a migration in the spec's `prepare`, and
//! warrants its own `Subprotocol` implementation rather than a second parameter here.

use strata_asm_bridge_types::{OperatorClaimUnlockV0, OperatorIdx};
use strata_asm_proto_bridge_state::operator::OperatorTable;

/// Selects the claim shape a bridge subprotocol version commits for a fulfilled withdrawal.
pub trait ClaimVersion: 'static {
    /// Computes the export leaf committed for a fulfilled assignment.
    ///
    /// Takes the operator table rather than the whole bridge state, so that a later change to
    /// the state container leaves the claim axis untouched.
    ///
    /// # Panics
    ///
    /// Panics if `assignee` is not in `operators`. Operator entries are never removed from the
    /// table, so an assignee always resolves; a miss means the assignment and the operator table
    /// have diverged.
    fn export_leaf(operators: &OperatorTable, deposit_idx: u32, assignee: OperatorIdx) -> [u8; 32];
}

/// Commits [`OperatorClaimUnlockV0`] leaves, naming the assignee by operator table index.
///
/// This is the shape deployed chains have already committed leaves under.
#[derive(Debug)]
pub struct ClaimV0;

impl ClaimVersion for ClaimV0 {
    fn export_leaf(
        _operators: &OperatorTable,
        deposit_idx: u32,
        assignee: OperatorIdx,
    ) -> [u8; 32] {
        OperatorClaimUnlockV0::new(deposit_idx, assignee).compute_hash()
    }
}
