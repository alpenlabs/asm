//! Impl blocks for checkpoint predicate transition types.

use strata_identifiers::L1Height;
use strata_predicate::PredicateKey;

use crate::PendingPredicateTransition;

impl PendingPredicateTransition {
    /// Creates a pending predicate transition.
    pub fn new(predicate: PredicateKey, boundary: L1Height) -> Self {
        Self {
            predicate,
            boundary,
        }
    }

    /// Returns the predicate that activates after the boundary.
    pub fn predicate(&self) -> &PredicateKey {
        &self.predicate
    }

    /// Returns the last L1 height governed by the preceding predicate.
    pub fn boundary(&self) -> L1Height {
        self.boundary
    }
}
