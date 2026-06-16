//! Generic backward-ancestry walk shared by workers that fold an L1 block
//! sequence forward from a stored base.
//!
//! Both the ASM worker (running the STF) and the Moho worker (folding
//! `MohoState`) advance per L1 block by finding the most recent ancestor whose
//! derived state is already stored — the *base* — and then (re)processing every
//! block above it. The backward search is identical; only the forward step
//! differs, so it stays in each worker.
//!
//! [`plan_sync`] performs just the search: walk parents from a tip back to
//! the base, collecting the unprocessed blocks in between. Walking real parents
//! (not heights) keeps it correct across an L1 reorg, where the base is the fork
//! point and the abandoned branch is never visited.

use std::error::Error;

use strata_identifiers::L1BlockCommitment;

/// The base to build on plus the unprocessed blocks between it and the tip,
/// produced by [`plan_sync`].
#[derive(Debug)]
pub struct SyncPlan<S> {
    /// Stored derived state at [`base_block`](Self::base_block) — the state the
    /// forward pass builds on.
    pub base_state: S,
    /// The most recent ancestor of the tip with a stored derived state (the
    /// reorg fork point, when there is a reorg).
    pub base_block: L1BlockCommitment,
    /// Unprocessed blocks between the base and the tip, newest first. Process
    /// them in reverse to apply them oldest first (contiguous, ascending
    /// heights).
    pub pending: Vec<L1BlockCommitment>,
}

/// Why [`plan_sync`] could not produce a plan.
#[derive(Debug, thiserror::Error)]
pub enum SyncError<E: Error> {
    /// The backward walk reached the floor height without finding a stored base
    /// state. The floor is the genesis height, whose state is always present, so
    /// this signals a corrupt or absent genesis.
    #[error("no base state at or above floor height {floor_height} walking back from {tip:?}")]
    ReachedFloor {
        tip: L1BlockCommitment,
        floor_height: u64,
    },

    /// A caller-supplied provider — base lookup or parent resolution — failed.
    #[error(transparent)]
    Provider(E),
}

/// Walks parents back from `tip` to the first block with a stored base state,
/// returning that base and the unprocessed blocks above it.
///
/// `base_at` returns `Some(state)` for a block whose derived state is already
/// stored — the search stops there — and `None` otherwise. `parent_of` resolves
/// a block's parent commitment. The walk fails with
/// [`ReachedFloor`](SyncError::ReachedFloor) if it descends to `floor_height`
/// without finding a base: set `floor_height` to the genesis height, whose state
/// is always stored, so a healthy chain terminates above it — or at it, with an
/// empty `pending` when the tip itself is already a base.
pub fn plan_sync<S, E>(
    tip: L1BlockCommitment,
    floor_height: u64,
    base_at: impl Fn(&L1BlockCommitment) -> Result<Option<S>, E>,
    parent_of: impl Fn(&L1BlockCommitment) -> Result<L1BlockCommitment, E>,
) -> Result<SyncPlan<S>, SyncError<E>>
where
    E: Error,
{
    let mut pending = Vec::new();
    let mut cursor = tip;
    loop {
        if let Some(base_state) = base_at(&cursor).map_err(SyncError::Provider)? {
            return Ok(SyncPlan {
                base_state,
                base_block: cursor,
                pending,
            });
        }

        if cursor.height() as u64 <= floor_height {
            return Err(SyncError::ReachedFloor { tip, floor_height });
        }

        let parent = parent_of(&cursor).map_err(SyncError::Provider)?;
        pending.push(cursor);
        cursor = parent;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

    use super::*;

    /// Provider error for exercising the [`SyncError::Provider`] path.
    #[derive(Debug, thiserror::Error)]
    #[error("provider boom")]
    struct Boom;

    fn blk(height: u32, id: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::from([id; 32])))
    }

    /// Runs [`plan_sync`] over an in-memory ancestry: `bases` are the blocks
    /// with a stored state, `parents` maps each block to its parent. The base
    /// payload is the block itself, so `base_state == base_block`.
    fn run(
        tip: L1BlockCommitment,
        floor_height: u64,
        bases: HashSet<L1BlockCommitment>,
        parents: HashMap<L1BlockCommitment, L1BlockCommitment>,
    ) -> Result<SyncPlan<L1BlockCommitment>, SyncError<Boom>> {
        plan_sync(
            tip,
            floor_height,
            |b| Ok(bases.contains(b).then_some(*b)),
            |b| parents.get(b).copied().ok_or(Boom),
        )
    }

    #[test]
    fn collects_linear_gap_back_to_base() {
        let genesis = blk(100, 0);
        let b1 = blk(101, 1);
        let b2 = blk(102, 2);
        let b3 = blk(103, 3);

        let plan = run(
            b3,
            100,
            HashSet::from([genesis]),
            HashMap::from([(b3, b2), (b2, b1), (b1, genesis)]),
        )
        .unwrap();

        assert_eq!(plan.base_block, genesis);
        // Newest first; the forward pass reverses to apply oldest first.
        assert_eq!(plan.pending, vec![b3, b2, b1]);
    }

    #[test]
    fn tip_already_base_yields_empty_pending() {
        let genesis = blk(100, 0);

        let plan = run(genesis, 100, HashSet::from([genesis]), HashMap::new()).unwrap();

        assert_eq!(plan.base_block, genesis);
        assert!(plan.pending.is_empty());
    }

    #[test]
    fn reorg_stops_at_fork_point_skipping_abandoned_branch() {
        // Both siblings build on genesis; the abandoned sibling `b_a` has a
        // stored state but is not on `b_b`'s ancestry, so it must not be visited.
        let genesis = blk(100, 0);
        let b_a = blk(101, 0xaa);
        let b_b = blk(101, 0xbb);

        let plan = run(
            b_b,
            100,
            HashSet::from([genesis, b_a]),
            HashMap::from([(b_b, genesis), (b_a, genesis)]),
        )
        .unwrap();

        assert_eq!(plan.base_block, genesis);
        assert_eq!(plan.pending, vec![b_b]);
    }

    #[test]
    fn reorg_stops_at_non_genesis_fork_point() {
        // The fork point `f` (102) is stored and sits above the floor (100), so
        // the walk must stop there rather than descending to genesis. The
        // abandoned branch's `a3` is stored at an intermediate height but is off
        // the new tip's ancestry, so it must never be visited. Together this
        // exercises the base-before-floor check at a non-floor base — the case
        // the other tests miss, since their base always equals the floor.
        let genesis = blk(100, 0);
        let f = blk(102, 0x0f); // stored base, above the floor
        let a3 = blk(103, 0xaa); // abandoned, stored, never on the b-branch
        let b3 = blk(103, 0xbb);
        let b4 = blk(104, 0xbb);

        let plan = run(
            b4,
            100,
            HashSet::from([genesis, f, a3]),
            HashMap::from([(b4, b3), (b3, f), (a3, f), (f, genesis)]),
        )
        .unwrap();

        assert_eq!(plan.base_block, f);
        assert_eq!(plan.pending, vec![b4, b3]);
        assert!(!plan.pending.contains(&a3));
    }

    #[test]
    fn reaching_floor_without_base_errors() {
        let b1 = blk(101, 1);
        let b2 = blk(102, 2);
        let floor = blk(100, 0);

        // No stored base anywhere, so the walk runs down to the floor.
        let err = run(
            b2,
            100,
            HashSet::new(),
            HashMap::from([(b2, b1), (b1, floor)]),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SyncError::ReachedFloor {
                floor_height: 100,
                ..
            }
        ));
    }

    #[test]
    fn provider_failure_propagates() {
        let b1 = blk(101, 1);
        // No parent registered, so `parent_of` errors before reaching a base.
        let err = run(b1, 100, HashSet::new(), HashMap::new()).unwrap_err();

        assert!(matches!(err, SyncError::Provider(Boom)));
    }
}
