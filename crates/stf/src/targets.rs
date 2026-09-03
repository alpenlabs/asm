//! Selecting which specification executes a block.
//!
//! A specification is target-fixed: [`AsmSpec::ID`] is a constant, and nothing
//! inside the transition chooses it. The choice is made once per block, from the
//! authenticated predicate the parent handed over — the same value the recursive
//! proof verifies each step against. Reading the rules off that value rather
//! than off a separately maintained schedule is what makes executor and verifier
//! agree structurally instead of by upkeep.
//!
//! An [`AsmTargetSet`] is the set of specifications one build can execute. It is
//! a compiled-in property of a release, never deployment configuration: a wrong
//! binding must be a wrong build, catchable before it runs, rather than a wrong
//! deployment that silently applies the wrong rules.

use bitcoin::Block;
use strata_asm_common::{
    AnchorState, AsmError, AsmResult, AsmSpec, AsmSpecId, AuxData, prepare_state, section_schema,
    validate_state_for_spec,
};
use strata_btc_verification::TxidInclusionProof;
use strata_predicate::PredicateKey;

use crate::{
    compute_asm_transition, pre_process_asm,
    types::{AsmPreProcessOutput, AsmStfOutput},
};

/// The specifications one build can execute, keyed by authorizing predicate.
///
/// Both execution methods take the predicate rather than a resolved
/// specification, so a caller cannot preprocess a block under one specification
/// and execute it under another. Each resolves and prepares state itself;
/// preparation is a pure function of the pre-state, so both observe the same
/// layout, including across a boundary migration.
pub trait AsmTargetSet: Send + Sync + 'static {
    /// Returns the specification `predicate` authorizes, or `None` when this
    /// build cannot execute it.
    ///
    /// `None` is not a soft condition: it means the chain has enacted rules this
    /// software does not implement, so the caller must stop rather than continue
    /// under whatever rules it happens to have.
    fn spec_id_for(&self, predicate: &PredicateKey) -> Option<AsmSpecId>;

    /// Returns the direct predecessor declared by `target`, if it has one.
    ///
    /// Stored-state adoption uses this semantic edge independently from schema
    /// inspection. Equal schemas do not make an arbitrary spec transition valid:
    /// a different target must explicitly name the spec that produced the anchor
    /// as its direct predecessor.
    fn direct_predecessor_of(&self, target: AsmSpecId) -> Option<AsmSpecId>;

    /// Fully validates stored state against the specification selected by
    /// `predicate`, without mutating or persisting it.
    ///
    /// A target-schema state is decoded canonically under the selected spec. A
    /// direct-predecessor state is accepted only by a target implementation
    /// that names that predecessor explicitly and successfully preflights the
    /// migration. The worker separately proves that the stored anchor was
    /// actually produced under that predecessor before accepting the boundary.
    fn validate_pre_state(
        &self,
        predicate: &PredicateKey,
        state: &AnchorState,
    ) -> AsmResult<PreStateValidation>;

    /// Collects the auxiliary-data requests for `block`.
    fn pre_process<'b>(
        &self,
        predicate: &PredicateKey,
        pre_state: &AnchorState,
        block: &'b Block,
    ) -> AsmResult<AsmPreProcessOutput<'b>>;

    /// Executes `block`, producing the successor state and its manifest.
    fn transition(
        &self,
        predicate: &PredicateKey,
        pre_state: &AnchorState,
        block: &Block,
        aux_data: &AuxData,
        coinbase_inclusion_proof: Option<&TxidInclusionProof>,
    ) -> AsmResult<AsmStfOutput>;
}

/// How stored state relates to the target selected for its child block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreStateValidation {
    /// State already has the selected target's schema and canonical payloads.
    TargetSchema,

    /// State is the exact direct predecessor and its migration preflight passed.
    DirectPredecessor {
        /// Specification that wrote the stored state.
        spec: AsmSpecId,
    },
}

/// Fully validates stored state for a specification with no accepted
/// predecessor at this target boundary.
pub fn validate_pre_state_for<S: AsmSpec>(state: &AnchorState) -> AsmResult<PreStateValidation> {
    validate_state_for_spec::<S>(state)?;
    Ok(PreStateValidation::TargetSchema)
}

/// Fully validates stored state for target `S` and its direct predecessor `P`.
///
/// This checks the release wiring as well as the bytes: `S` must declare `P` by
/// both semantic id and derived schema. Predecessor payloads are decoded
/// canonically under `P`, then `S`'s migration runs as a pure preflight and its
/// output is validated by [`prepare_state`]. The migrated value is dropped;
/// startup never rewrites the persisted boundary state.
pub fn validate_pre_state_with_predecessor_for<S, P>(
    state: &AnchorState,
) -> AsmResult<PreStateValidation>
where
    S: AsmSpec,
    P: AsmSpec,
{
    let predecessor = S::predecessor().ok_or(AsmError::NoMigrationDefined { into: S::ID })?;
    if predecessor.id() != P::ID {
        return Err(AsmError::PredecessorSpecMismatch {
            into: S::ID,
            declared: predecessor.id(),
            validator: P::ID,
        });
    }
    if predecessor.schema() != section_schema::<P>() {
        return Err(AsmError::PredecessorSchemaMismatch {
            into: S::ID,
            predecessor: P::ID,
        });
    }

    // Preserve structural errors as structural errors. They are not evidence
    // that state belongs to another specification and must not enter migration.
    state.validate()?;

    if state.validate_schema(&section_schema::<S>()).is_ok() {
        validate_state_for_spec::<S>(state)?;
        return Ok(PreStateValidation::TargetSchema);
    }

    state
        .validate_schema(predecessor.schema())
        .map_err(|source| AsmError::MigrationInputRejected {
            into: S::ID,
            source,
        })?;
    validate_state_for_spec::<P>(state)?;

    let prepared = prepare_state::<S>(state)?;
    debug_assert!(
        prepared.was_migrated(),
        "target-schema state returned through the predecessor path"
    );

    Ok(PreStateValidation::DirectPredecessor { spec: P::ID })
}

/// Collects aux requests for `block` under specification `S`.
///
/// A free function so each arm of an [`AsmTargetSet`] implementation is one
/// line: the prepare-then-preprocess sequence is written once here and
/// monomorphized per specification.
pub fn pre_process_for<'b, S: AsmSpec>(
    pre_state: &AnchorState,
    block: &'b Block,
) -> AsmResult<AsmPreProcessOutput<'b>> {
    let prepared = prepare_state::<S>(pre_state)?;
    pre_process_asm(&prepared, block)
}

/// Executes `block` under specification `S`. See [`pre_process_for`].
pub fn transition_for<S: AsmSpec>(
    pre_state: &AnchorState,
    block: &Block,
    aux_data: &AuxData,
    coinbase_inclusion_proof: Option<&TxidInclusionProof>,
) -> AsmResult<AsmStfOutput> {
    let prepared = prepare_state::<S>(pre_state)?;
    compute_asm_transition(&prepared, block, aux_data, coinbase_inclusion_proof)
}
