//! In-memory pending proof queue.
//!
//! Tracks proofs that need to be generated but have not yet been submitted to
//! the remote prover. Entries are ordered according to [`ProofId`]'s [`Ord`]
//! implementation: Moho proofs first (critical path for recursion), then ASM
//! proofs, both in ascending height order.

use std::collections::BTreeSet;

use strata_asm_prover_types::ProofId;

/// In-memory queue of proofs awaiting generation.
///
/// Uses a [`BTreeSet`] backed by [`ProofId`]'s [`Ord`] implementation, which
/// prioritises Moho proofs over ASM proofs and orders by ascending height
/// within each variant. Duplicate entries are automatically ignored.
#[derive(Debug)]
pub(crate) struct PendingProofQueue {
    pending: BTreeSet<ProofId>,
}

impl PendingProofQueue {
    /// Creates an empty queue.
    pub(crate) fn new() -> Self {
        Self {
            pending: BTreeSet::new(),
        }
    }

    /// Enqueues a proof for generation.
    ///
    /// If the same [`ProofId`] is already present it is not duplicated.
    pub(crate) fn enqueue(&mut self, id: ProofId) {
        self.pending.insert(id);
    }

    /// Removes and returns the next entry in priority order, if any.
    pub(crate) fn dequeue_one(&mut self) -> Option<ProofId> {
        self.pending.pop_first()
    }

    pub(crate) fn len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_prover_types::L1Range;
    use strata_identifiers::{L1BlockCommitment, L1BlockId};

    use super::*;

    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::default())
    }

    fn asm(height: u32) -> ProofId {
        ProofId::Asm(L1Range::single(commitment(height)))
    }

    fn moho(height: u32) -> ProofId {
        ProofId::Moho(commitment(height))
    }

    #[test]
    fn asm_before_moho_at_same_height() {
        let mut q = PendingProofQueue::new();
        q.enqueue(moho(3));
        q.enqueue(asm(3));

        assert!(matches!(q.dequeue_one(), Some(ProofId::Asm(_))));
        assert!(matches!(q.dequeue_one(), Some(ProofId::Moho(_))));
    }

    #[test]
    fn lowest_height_first_across_variants() {
        let mut q = PendingProofQueue::new();
        q.enqueue(moho(2));
        q.enqueue(asm(5));

        assert!(matches!(q.dequeue_one(), Some(ProofId::Moho(_))));
        assert!(matches!(q.dequeue_one(), Some(ProofId::Asm(_))));
    }

    #[test]
    fn ascending_height_within_variant() {
        let mut q = PendingProofQueue::new();
        q.enqueue(asm(5));
        q.enqueue(asm(2));
        q.enqueue(asm(8));

        assert_eq!(q.dequeue_one(), Some(asm(2)));
        assert_eq!(q.dequeue_one(), Some(asm(5)));
        assert_eq!(q.dequeue_one(), Some(asm(8)));
    }

    #[test]
    fn dequeue_one_on_empty() {
        let mut q = PendingProofQueue::new();
        assert_eq!(q.dequeue_one(), None);
    }

    #[test]
    fn dedup() {
        let mut q = PendingProofQueue::new();
        q.enqueue(asm(3));
        q.enqueue(asm(3));
        q.enqueue(moho(3));
        q.enqueue(moho(3));
        assert_eq!(q.len(), 2);
    }
}
