//! In-memory pending proof queue.
//!
//! Tracks proofs that need to be generated but have not yet been submitted to
//! the remote prover. Entries are ordered according to [`ProofId`]'s [`Ord`]
//! implementation: Moho proofs first (critical path for recursion), then ASM
//! proofs, both in ascending height order.

use std::collections::BTreeSet;

use strata_asm_proof_types::ProofId;

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

    /// Removes and returns up to `count` entries in priority order.
    pub(crate) fn dequeue_batch(&mut self, count: usize) -> Vec<ProofId> {
        let mut batch = Vec::with_capacity(count);

        while batch.len() < count {
            let Some(id) = self.pending.pop_first() else {
                break;
            };
            batch.push(id);
        }

        batch
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
    use strata_asm_proof_types::L1Range;
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

        let batch = q.dequeue_batch(10);
        assert!(matches!(batch[0], ProofId::Asm(_)));
        assert!(matches!(batch[1], ProofId::Moho(_)));
    }

    #[test]
    fn lowest_height_first_across_variants() {
        let mut q = PendingProofQueue::new();
        q.enqueue(moho(2));
        q.enqueue(asm(5));

        let batch = q.dequeue_batch(10);
        assert!(matches!(batch[0], ProofId::Moho(_)));
        assert!(matches!(batch[1], ProofId::Asm(_)));
    }

    #[test]
    fn ascending_height_within_variant() {
        let mut q = PendingProofQueue::new();
        q.enqueue(asm(5));
        q.enqueue(asm(2));
        q.enqueue(asm(8));

        let batch = q.dequeue_batch(10);
        assert_eq!(batch, vec![asm(2), asm(5), asm(8)]);
    }

    #[test]
    fn dequeue_batch_limits_count() {
        let mut q = PendingProofQueue::new();
        for h in 0..10 {
            q.enqueue(asm(h));
        }

        let batch = q.dequeue_batch(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch, vec![asm(0), asm(1), asm(2)]);
        assert_eq!(q.len(), 7);
    }

    #[test]
    fn dequeue_batch_on_empty() {
        let mut q = PendingProofQueue::new();
        assert!(q.dequeue_batch(5).is_empty());
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
