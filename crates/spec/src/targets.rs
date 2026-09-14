//! The release's predicate-to-specification table.
//!
//! # Why this is compiled in rather than configured
//!
//! Which rules a block runs under is decided by the predicate its parent handed
//! over, so the predicate-to-specification binding is consensus-relevant. If it
//! were deployment configuration, a mistyped entry would make a node execute the
//! wrong rules for a predicate — producing state no proof can be made for, and
//! doing so silently on a node that does not prove.
//!
//! Pinning the table in the release turns that class of mistake from a wrong
//! *deployment* into a wrong *build*: reviewed once, identical everywhere, and
//! catchable before it runs. Operators supply artifact paths, never this
//! mapping.
//!
//! # Where a node's bindings actually come from
//!
//! A *proving* node selects entries from the same immutable release manifests by
//! artifact ID. Each entry binds its semantic specification, predicate, ELF
//! digest, VK digest, source revision, and build identity. Startup hashes the
//! supplied files and derives the predicate from the verified ELF before the
//! runner builds this table. Operators supply paths and artifact IDs; they never
//! supply the semantic mapping.
//!
//! A node that does *not* prove has no artifacts to derive from, and the ASM
//! worker deliberately carries no proving stack. It runs with the one binding it
//! can be certain of — the chain's genesis predicate — and halts on the first
//! predicate it cannot resolve. Following across an upgrade boundary requires
//! the successor's final artifact manifest to be compiled into the release
//! before governance enacts its predicate. An unknown predicate is a safe halt,
//! never a guessed target.

use bitcoin::Block;
use strata_asm_common::{AnchorState, AsmResult, AsmSpec, AsmSpecId, AuxData};
use strata_asm_stf::{
    AsmPreProcessOutput, AsmStfOutput, AsmTargetSet, PreStateValidation, pre_process_for,
    transition_for, validate_pre_state_for, validate_pre_state_with_predecessor_for,
};
use strata_btc_verification::TxidInclusionProof;
use strata_predicate::PredicateKey;

use crate::{StrataAsmSpecV0, StrataAsmSpecV1};

/// A locally compiled specification, selected by predicate.
///
/// One variant per specification this build can execute. The enum exists because
/// [`AsmSpec::ID`] is an associated constant — a specification cannot vary its
/// own identity — so choosing between specifications is an explicit match rather
/// than a value that could drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrataAsmTarget {
    /// The rules as released in `v0.3.0-rc.2`.
    V0,
    /// The current rules.
    V1,
}

impl StrataAsmTarget {
    /// Returns the semantic identity of this target's specification.
    pub const fn spec_id(self) -> AsmSpecId {
        match self {
            Self::V0 => StrataAsmSpecV0::ID,
            Self::V1 => StrataAsmSpecV1::ID,
        }
    }

    /// Returns the target implementing `spec_id`.
    ///
    /// Total by construction: the match is exhaustive over [`AsmSpecId`], so a
    /// new specification cannot be introduced without giving this build a target
    /// that executes it. That is what lets a proving node turn the
    /// specifications its artifacts declare into a target table without any
    /// possibility of an unmapped id.
    pub const fn for_spec_id(spec_id: AsmSpecId) -> Self {
        match spec_id {
            AsmSpecId::V0 => Self::V0,
            AsmSpecId::V1 => Self::V1,
        }
    }
}

/// The release's predicate-to-target table.
///
/// Entries are added, never edited or removed: a node replaying history resolves
/// every predicate the chain has ever enacted, so an old entry stays meaningful
/// forever.
#[derive(Debug, Clone)]
pub struct StrataAsmTargets {
    entries: Vec<(PredicateKey, StrataAsmTarget)>,
}

/// A table that could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetTableError {
    /// Two entries claim the same predicate.
    ///
    /// A predicate must name exactly one specification, or which rules a block
    /// runs under would depend on lookup order.
    #[error("predicate {predicate:?} is bound to more than one specification")]
    AmbiguousPredicate {
        /// The repeated predicate.
        predicate: PredicateKey,
    },
}

impl StrataAsmTargets {
    /// Builds the table from the release's bindings.
    ///
    /// Ambiguity is the one invariant checkable here, and it is checked: a
    /// predicate must name exactly one specification.
    ///
    /// *Coverage* — that the table binds every predicate the chain can hand over
    /// — is not checkable statically, because which predicates a chain will
    /// enact is not known when the release is built. It is enforced where the
    /// answer exists instead: the worker refuses to start, and refuses each
    /// block, on a predicate that does not resolve. A release that omits a
    /// binding therefore halts loudly rather than executing the wrong rules.
    ///
    /// A chain that has not upgraded legitimately needs only one binding, so a
    /// single-entry table is valid.
    pub fn new(bindings: Vec<(PredicateKey, StrataAsmTarget)>) -> Result<Self, TargetTableError> {
        for (index, (predicate, _)) in bindings.iter().enumerate() {
            if bindings[..index]
                .iter()
                .any(|(prior, _)| prior == predicate)
            {
                return Err(TargetTableError::AmbiguousPredicate {
                    predicate: predicate.clone(),
                });
            }
        }

        Ok(Self { entries: bindings })
    }

    /// Resolves a predicate to its target.
    pub fn resolve(&self, predicate: &PredicateKey) -> Option<StrataAsmTarget> {
        self.entries
            .iter()
            .find(|(known, _)| known == predicate)
            .map(|(_, target)| *target)
    }

    /// Returns every binding, for diagnostics and startup cross-checks.
    pub fn entries(&self) -> &[(PredicateKey, StrataAsmTarget)] {
        &self.entries
    }
}

impl AsmTargetSet for StrataAsmTargets {
    fn spec_id_for(&self, predicate: &PredicateKey) -> Option<AsmSpecId> {
        self.resolve(predicate).map(StrataAsmTarget::spec_id)
    }

    fn direct_predecessor_of(&self, target: AsmSpecId) -> Option<AsmSpecId> {
        match target {
            AsmSpecId::V0 => StrataAsmSpecV0::predecessor().map(|predecessor| predecessor.id()),
            AsmSpecId::V1 => StrataAsmSpecV1::predecessor().map(|predecessor| predecessor.id()),
        }
    }

    fn validate_pre_state(
        &self,
        predicate: &PredicateKey,
        state: &AnchorState,
    ) -> AsmResult<PreStateValidation> {
        match self.resolve(predicate) {
            Some(StrataAsmTarget::V0) => validate_pre_state_for::<StrataAsmSpecV0>(state),
            Some(StrataAsmTarget::V1) => {
                validate_pre_state_with_predecessor_for::<StrataAsmSpecV1, StrataAsmSpecV0>(state)
            }
            None => Err(unsupported(predicate)),
        }
    }

    fn pre_process<'b>(
        &self,
        predicate: &PredicateKey,
        pre_state: &AnchorState,
        block: &'b Block,
    ) -> AsmResult<AsmPreProcessOutput<'b>> {
        match self.resolve(predicate) {
            Some(StrataAsmTarget::V0) => pre_process_for::<StrataAsmSpecV0>(pre_state, block),
            Some(StrataAsmTarget::V1) => pre_process_for::<StrataAsmSpecV1>(pre_state, block),
            // The caller checks `spec_id_for` first and halts, so this is
            // unreachable on the worker path; failing here rather than guessing
            // keeps that a fact rather than a convention.
            None => Err(unsupported(predicate)),
        }
    }

    fn transition(
        &self,
        predicate: &PredicateKey,
        pre_state: &AnchorState,
        block: &Block,
        aux_data: &AuxData,
        coinbase_inclusion_proof: Option<&TxidInclusionProof>,
    ) -> AsmResult<AsmStfOutput> {
        match self.resolve(predicate) {
            Some(StrataAsmTarget::V0) => transition_for::<StrataAsmSpecV0>(
                pre_state,
                block,
                aux_data,
                coinbase_inclusion_proof,
            ),
            Some(StrataAsmTarget::V1) => transition_for::<StrataAsmSpecV1>(
                pre_state,
                block,
                aux_data,
                coinbase_inclusion_proof,
            ),
            None => Err(unsupported(predicate)),
        }
    }
}

fn unsupported(predicate: &PredicateKey) -> strata_asm_common::AsmError {
    strata_asm_common::AsmError::UnsupportedPredicate {
        predicate: format!("{predicate:?}"),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        BlockHash, CompactTarget, TxMerkleNode,
        block::{Header, Version as BlockVersion},
        hashes::Hash,
    };
    use strata_predicate::PredicateTypeId;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    fn table() -> StrataAsmTargets {
        StrataAsmTargets::new(vec![
            (predicate(1), StrataAsmTarget::V0),
            (predicate(2), StrataAsmTarget::V1),
        ])
        .expect("valid table")
    }

    #[test]
    fn resolves_each_predicate_to_its_specification() {
        let table = table();

        assert_eq!(table.resolve(&predicate(1)), Some(StrataAsmTarget::V0));
        assert_eq!(table.resolve(&predicate(2)), Some(StrataAsmTarget::V1));
        assert_eq!(table.spec_id_for(&predicate(1)), Some(AsmSpecId::V0));
        assert_eq!(table.spec_id_for(&predicate(2)), Some(AsmSpecId::V1));
    }

    /// An unknown predicate resolves to nothing rather than to a default. The
    /// chain has enacted rules this build lacks, and guessing would produce state
    /// no proof can be made for.
    #[test]
    fn an_unknown_predicate_resolves_to_nothing() {
        let table = table();
        assert_eq!(table.resolve(&predicate(9)), None);
        assert_eq!(table.spec_id_for(&predicate(9)), None);
    }

    /// One predicate must name one specification, or which rules a block runs
    /// under would depend on lookup order.
    #[test]
    fn a_predicate_bound_twice_is_rejected() {
        assert_eq!(
            StrataAsmTargets::new(vec![
                (predicate(1), StrataAsmTarget::V0),
                (predicate(1), StrataAsmTarget::V1),
            ])
            .unwrap_err(),
            TargetTableError::AmbiguousPredicate {
                predicate: predicate(1)
            },
        );
    }

    /// A chain that has not upgraded needs only one binding. Coverage is
    /// enforced by the worker halting on an unresolvable predicate, not by
    /// guessing here which specifications a deployment will need.
    #[test]
    fn a_single_binding_is_valid() {
        let table = StrataAsmTargets::new(vec![(predicate(2), StrataAsmTarget::V1)])
            .expect("a chain that has not upgraded needs one binding");

        assert_eq!(table.resolve(&predicate(2)), Some(StrataAsmTarget::V1));
        assert_eq!(table.resolve(&predicate(1)), None);
    }

    /// Execution refuses an unresolvable predicate rather than falling back to a
    /// specification it does have. This is the property the whole model rests
    /// on: continuing under the wrong rules would produce state no proof can
    /// ever be made for, and would do so silently on a node that does not prove.
    #[test]
    fn execution_refuses_an_unresolvable_predicate() {
        use strata_asm_common::AsmError;

        let table = table();
        let state = crate::construct_v0_genesis_state(&ArbitraryGenerator::new().generate());
        let block = Block {
            header: Header {
                version: BlockVersion::ONE,
                prev_blockhash: BlockHash::from_byte_array([0; 32]),
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: 0,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: Vec::new(),
        };

        assert!(matches!(
            table.pre_process(&predicate(9), &state, &block),
            Err(AsmError::UnsupportedPredicate { .. })
        ));
        assert!(matches!(
            table.transition(&predicate(9), &state, &block, &AuxData::default(), None),
            Err(AsmError::UnsupportedPredicate { .. })
        ));
    }

    /// Startup accepts a fully decoded steady state and the one exact direct
    /// predecessor, reporting which case it observed so the worker can
    /// authenticate an actual activation boundary for the latter.
    #[test]
    fn startup_validation_distinguishes_steady_and_direct_predecessor_state() {
        let table = table();
        let params = ArbitraryGenerator::new().generate();
        let baseline = crate::construct_v0_genesis_state(&params);
        let successor = crate::construct_v1_genesis_state(&params);

        assert_eq!(
            table
                .validate_pre_state(&predicate(1), &baseline)
                .expect("baseline steady state validates"),
            PreStateValidation::TargetSchema,
        );
        assert_eq!(
            table
                .validate_pre_state(&predicate(2), &successor)
                .expect("successor steady state validates"),
            PreStateValidation::TargetSchema,
        );
        assert_eq!(
            table
                .validate_pre_state(&predicate(2), &baseline)
                .expect("direct predecessor migration preflight validates"),
            PreStateValidation::DirectPredecessor {
                spec: AsmSpecId::V0,
            },
        );
        assert_eq!(
            baseline,
            crate::construct_v0_genesis_state(&params),
            "migration preflight must not mutate predecessor state",
        );
    }

    /// A matching section id with an unrelated codec version is neither target
    /// nor predecessor state and must not be treated as a migration candidate.
    #[test]
    fn startup_validation_rejects_an_unrelated_schema() {
        let table = table();
        let mut state = crate::construct_v0_genesis_state(&ArbitraryGenerator::new().generate());
        state.sections[0].version = u8::MAX;

        assert!(matches!(
            table.validate_pre_state(&predicate(2), &state),
            Err(strata_asm_common::AsmError::MigrationInputRejected { .. })
        ));
    }

    /// Codec versions do not make opaque payload bytes trustworthy. A stored
    /// steady state must decode canonically under the selected specification.
    #[test]
    fn startup_validation_rejects_a_malformed_steady_payload() {
        let table = table();
        let mut state = crate::construct_v0_genesis_state(&ArbitraryGenerator::new().generate());
        let section = &state.sections[0];
        state.sections[0] = strata_asm_common::SectionState::new(
            section.id,
            section.version,
            vec![0xff, 0xff, 0xff],
        )
        .expect("malformed payload fits the section envelope");

        assert!(table.validate_pre_state(&predicate(1), &state).is_err());
    }

    /// Every specification id maps to a target and back, so a table built from
    /// the specifications a node's artifacts declare cannot contain an id this
    /// build has no target for.
    #[test]
    fn spec_ids_and_targets_are_in_bijection() {
        for spec_id in [AsmSpecId::V0, AsmSpecId::V1] {
            assert_eq!(StrataAsmTarget::for_spec_id(spec_id).spec_id(), spec_id);
        }
        for target in [StrataAsmTarget::V0, StrataAsmTarget::V1] {
            assert_eq!(StrataAsmTarget::for_spec_id(target.spec_id()), target);
        }
    }

    /// Stored-state provenance checks use the same direct predecessor edge the
    /// successor spec declares for migration; the target table must not carry a
    /// second independently maintained upgrade graph.
    #[test]
    fn target_predecessors_are_derived_from_the_specs() {
        let table = table();
        assert_eq!(table.direct_predecessor_of(AsmSpecId::V0), None);
        assert_eq!(
            table.direct_predecessor_of(AsmSpecId::V1),
            Some(AsmSpecId::V0),
        );
    }

    /// Two predicates may name the *same* specification — a verifying-key
    /// rotation that changes no rules is an ordinary upgrade under this model,
    /// needing no new specification and no special case.
    #[test]
    fn two_predicates_may_share_a_specification() {
        let table = StrataAsmTargets::new(vec![
            (predicate(1), StrataAsmTarget::V0),
            (predicate(2), StrataAsmTarget::V0),
        ])
        .expect("a rotation without a rule change is valid");

        assert_eq!(table.resolve(&predicate(1)), Some(StrataAsmTarget::V0));
        assert_eq!(table.resolve(&predicate(2)), Some(StrataAsmTarget::V0));
    }
}
