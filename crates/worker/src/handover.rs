//! The predicate handover chain.
//!
//! Which rules a block executes under is decided by the predicate its parent
//! handed over — the same value the recursive proof verifies each step against.
//! Reading the rules off that value rather than off a separately maintained
//! schedule is what makes executor and verifier agree structurally instead of
//! by upkeep.
//!
//! The ASM worker cannot ask the Moho worker for it: Moho depends on ASM, so the
//! query would invert the dependency. It therefore derives the same chain
//! itself, from the same `AsmStfUpdate` logs, and persists one entry per block.
//!
//! Ordering is the crash-safety contract. An entry is written *before* the
//! block's anchor state commits, so a committed anchor never lacks the handover
//! it enacted. A replay of an uncommitted block rewrites the same entry, since
//! the STF is deterministic.

use strata_asm_common::AsmManifest;
use strata_asm_logs::extract_next_predicate_from_logs;
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;

use crate::WorkerResult;

/// Derives the predicate that authorizes the block after this one.
///
/// A block that enacts an ASM VK upgrade hands over the enacted predicate; every
/// other block hands over the one it ran under.
///
/// The enacting log is selected by
/// [`extract_next_predicate_from_logs`] — the same function the Moho program
/// calls, deliberately rather than a second implementation of the same rule.
/// Two derivations could disagree on a block carrying more than one update, and
/// the worker would then execute the next block under rules no proof authorizes.
pub fn derive_next_predicate(current: &PredicateKey, manifest: &AsmManifest) -> PredicateKey {
    extract_next_predicate_from_logs(manifest.logs()).unwrap_or_else(|| current.clone())
}

/// Persistence for the predicate handover chain.
pub trait AsmHandoverStore {
    /// Records the predicate that authorizes the block *after* `block`.
    ///
    /// Called before `block`'s anchor state is committed. Idempotent: replaying
    /// an uncommitted block rewrites the same entry.
    fn store_next_predicate(
        &self,
        block: &L1BlockCommitment,
        predicate: &PredicateKey,
    ) -> WorkerResult<()>;

    /// Returns the predicate that authorizes the block after `block`, if the
    /// handover for `block` has been recorded.
    fn get_next_predicate(&self, block: &L1BlockCommitment) -> WorkerResult<Option<PredicateKey>>;
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{AsmLogEntry, AsmManifest};
    use strata_asm_logs::AsmStfUpdate;
    use strata_identifiers::{Buf32, L1BlockId, WtxidsRoot};
    use strata_predicate::{PredicateKey, PredicateTypeId};

    use super::*;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    fn upgrade_log(to: &PredicateKey) -> AsmLogEntry {
        AsmLogEntry::from_log(&AsmStfUpdate::new(to.clone()))
            .expect("AsmStfUpdate encoding is infallible")
    }

    fn manifest(logs: Vec<AsmLogEntry>) -> AsmManifest {
        AsmManifest::new(
            7,
            L1BlockId::from(Buf32::from([9u8; 32])),
            WtxidsRoot::from(Buf32::from([3u8; 32])),
            logs,
        )
        .expect("manifest fits")
    }

    /// A block that enacts nothing hands over the predicate it ran under, so the
    /// chain continues unchanged.
    #[test]
    fn a_block_without_an_upgrade_carries_the_predicate() {
        let current = predicate(1);
        assert_eq!(
            derive_next_predicate(&current, &manifest(Vec::new())),
            current,
        );
    }

    /// A block that enacts an upgrade hands over the enacted predicate, which is
    /// what moves the next block onto the new rules.
    #[test]
    fn an_upgrade_hands_over_the_enacted_predicate() {
        let current = predicate(1);
        let enacted = predicate(2);

        assert_eq!(
            derive_next_predicate(&current, &manifest(vec![upgrade_log(&enacted)])),
            enacted,
        );
    }

    /// A block carrying two upgrades must hand over the same predicate the proof
    /// chain does. Asserting against the shared function rather than a literal
    /// means this keeps holding if the tie-break ever changes — and fails
    /// immediately if the worker stops using it.
    #[test]
    fn several_upgrades_agree_with_the_proof_chain() {
        let current = predicate(1);
        let m = manifest(vec![upgrade_log(&predicate(2)), upgrade_log(&predicate(3))]);

        assert_eq!(
            derive_next_predicate(&current, &m),
            strata_asm_logs::extract_next_predicate_from_logs(m.logs())
                .expect("the block enacts an upgrade"),
        );
    }

    /// Derivation is a pure function of the current predicate and the manifest,
    /// so re-running a block reproduces the same handover — which is what makes
    /// the write idempotent.
    #[test]
    fn derivation_is_deterministic() {
        let current = predicate(1);
        let enacted = predicate(2);
        let m = manifest(vec![upgrade_log(&enacted)]);

        assert_eq!(
            derive_next_predicate(&current, &m),
            derive_next_predicate(&current, &m),
        );
    }
}
