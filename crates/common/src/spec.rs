//! The ASM specification: one fixed set of consensus rules.
//!
//! A specification answers exactly one question — *what are the rules?* It
//! declares the active subprotocols in execution order, and how to convert a
//! predecessor's state into its own. Genesis construction lives elsewhere
//! (see [`AsmGenesis`](crate::AsmGenesis)); it runs once per chain, from
//! operator params, and is not a transition concern.
//!
//! A spec is **target-fixed**: [`AsmSpec::ID`] is an associated constant, so no
//! implementation can vary its identity at runtime. Which spec executes a block
//! is decided outside the transition, by the authenticated predicate handover.
//! Neither the block's contents nor its height reaches that decision.

use std::{borrow::Cow, fmt, marker::PhantomData};

use crate::{
    AnchorState, AsmError, AsmResult, AsmSpecId, SectionSchema, SectionStateExt, Subprotocol,
};

/// One fixed ASM specification.
pub trait AsmSpec: Sized + 'static {
    /// Semantic identity of these rules.
    ///
    /// An associated constant, not a method: a specification that could report
    /// a different id per call would defeat target-fixity.
    const ID: AsmSpecId;

    /// Invokes every active subprotocol in consensus execution order.
    ///
    /// The order is consensus-relevant and MUST be identical on every walk.
    /// This declaration is the single source of truth for the active set: the
    /// section schema is derived from it (see [`section_schema`]), so a spec
    /// cannot declare a pipeline and a schema that disagree.
    fn call_subprotocols(stage: &mut impl Stage);

    /// Returns the exact specification that may migrate into this one.
    ///
    /// `None` means this specification has no predecessor. A successor declares
    /// both the predecessor's semantic id and its exact section schema as one
    /// value, so startup validation cannot accidentally pair a migration with a
    /// different specification that happens to have compatible bytes.
    fn predecessor() -> Option<AsmSpecPredecessor> {
        None
    }

    /// Converts a direct predecessor's state into this specification's schema.
    ///
    /// Called only when the input does not already match this spec's schema,
    /// and only for a single upgrade hop — a node crossing several boundaries
    /// executes each one's boundary block in turn, so no implementation needs
    /// to handle a state older than its immediate predecessor.
    ///
    /// Implementations convert; they do not decide *whether* to convert. The
    /// framework owns that decision and verifies the result against this
    /// spec's schema afterwards, so a migration cannot quietly emit something
    /// the pipeline could not load.
    ///
    /// The default rejects: the first specification has no predecessor.
    fn migrate_state(_pre_state: &AnchorState) -> AsmResult<AnchorState> {
        Err(AsmError::NoMigrationDefined { into: Self::ID })
    }
}

/// The one specification whose state may migrate into a successor.
///
/// The semantic id and schema are deliberately inseparable. The id establishes
/// the authenticated rule-to-rule edge, while the schema establishes which
/// bytes that predecessor writes. Startup checks both before treating stored
/// state as an activation-boundary input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmSpecPredecessor {
    id: AsmSpecId,
    schema: Vec<SectionSchema>,
}

impl AsmSpecPredecessor {
    /// Builds a declaration from the predecessor specification itself.
    pub fn of<P: AsmSpec>() -> Self {
        Self {
            id: P::ID,
            schema: section_schema::<P>(),
        }
    }

    /// Returns the predecessor's semantic specification id.
    pub const fn id(&self) -> AsmSpecId {
        self.id
    }

    /// Returns the exact section schema the predecessor writes.
    pub fn schema(&self) -> &[SectionSchema] {
        &self.schema
    }
}

/// Impl of a subprotocol execution stage.
pub trait Stage {
    /// Invoked by the ASM spec to perform the stage's logic with respect to
    /// the subprotocol.
    fn invoke_subprotocol<S: Subprotocol>(&mut self);
}

/// State validated for one specification, ready to execute.
///
/// The lifetime lets the steady path borrow the caller's state: only a boundary
/// block, where a migration produced new bytes, needs to own anything. The
/// `S` brand makes it a compile error to prepare state for one specification
/// and execute it under another, so preprocessing and the transition provably
/// observe the same layout.
///
/// Constructors are crate-private: a `PreparedState` is evidence that
/// [`prepare_state`] ran, and no caller may manufacture that evidence.
pub struct PreparedState<'a, S: AsmSpec> {
    state: Cow<'a, AnchorState>,
    _spec: PhantomData<fn() -> S>,
}

impl<S: AsmSpec> fmt::Debug for PreparedState<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedState")
            .field("spec", &S::ID)
            .field("migrated", &self.was_migrated())
            .finish_non_exhaustive()
    }
}

impl<'a, S: AsmSpec> PreparedState<'a, S> {
    pub(crate) fn borrowed(state: &'a AnchorState) -> Self {
        Self {
            state: Cow::Borrowed(state),
            _spec: PhantomData,
        }
    }

    pub(crate) fn owned(state: AnchorState) -> Self {
        Self {
            state: Cow::Owned(state),
            _spec: PhantomData,
        }
    }

    /// Borrows the state every phase of this transition must observe.
    pub fn state(&self) -> &AnchorState {
        self.state.as_ref()
    }

    /// Returns whether preparation migrated the input.
    ///
    /// True on a boundary block only. Reported for diagnostics; nothing in the
    /// transition branches on it.
    pub fn was_migrated(&self) -> bool {
        matches!(self.state, Cow::Owned(_))
    }

    /// Takes the prepared state, cloning only if it was borrowed.
    pub fn into_owned(self) -> AnchorState {
        self.state.into_owned()
    }
}

/// Returns the section schema `S` reads and writes.
///
/// Derived from [`AsmSpec::call_subprotocols`] rather than declared separately:
/// each invoked subprotocol contributes `(S::ID, S::STATE_VERSION)`. The list
/// is in execution order, which is not required to be section order.
pub fn section_schema<S: AsmSpec>() -> Vec<SectionSchema> {
    let mut stage = SchemaStage::default();
    S::call_subprotocols(&mut stage);
    stage.schema
}

/// Validates and, if needed, migrates `pre_state` for execution under `S`.
///
/// This is the one place the migration decision is made, and it is made from
/// facts every executor of `S` shares: the schema `S` declares, and the codec
/// versions the state itself carries. It never consults a height, an activation
/// schedule, or anything else a guest could not reproduce — a native worker and
/// a guest artifact for `S` therefore always reach the same conclusion for the
/// same input.
///
/// The decision is idempotent by construction. State already at `S`'s schema is
/// passed through, so re-running a boundary block, or running the block after
/// it, cannot migrate twice.
///
/// Section payloads are not decoded on the steady path; the `LOAD` stage decodes
/// them, and duplicating that here would cost a second full decode on every
/// block. A migration's output *is* fully decoded, because that path runs once
/// per upgrade and is the one that just produced new bytes.
pub fn prepare_state<S: AsmSpec>(pre_state: &AnchorState) -> AsmResult<PreparedState<'_, S>> {
    // Structural failures are reported as themselves. Only a well-formed state
    // that belongs to this spec's exact predecessor is a migration candidate.
    pre_state.validate()?;

    let schema = section_schema::<S>();
    if pre_state.validate_schema(&schema).is_ok() {
        return Ok(PreparedState::borrowed(pre_state));
    }

    let predecessor = S::predecessor().ok_or(AsmError::NoMigrationDefined { into: S::ID })?;
    pre_state
        .validate_schema(predecessor.schema())
        .map_err(|source| AsmError::MigrationInputRejected {
            into: S::ID,
            source,
        })?;

    let migrated = S::migrate_state(pre_state)?;
    migrated
        .validate_schema(&schema)
        .map_err(|source| AsmError::MigrationOutputRejected {
            into: S::ID,
            source,
        })?;
    validate_payloads::<S>(&migrated)?;
    Ok(PreparedState::owned(migrated))
}

/// Fully validates that `state` is executable under `S`: exact section
/// membership, declared codec versions, and payloads that decode as `S`'s own
/// state types.
///
/// Used at boundaries where a full check is worth its cost — genesis
/// construction, loading state from storage — rather than on the per-block path.
pub fn validate_state_for_spec<S: AsmSpec>(state: &AnchorState) -> AsmResult<()> {
    state.validate_schema(&section_schema::<S>())?;
    validate_payloads::<S>(state)
}

/// Decodes every section declared by `S` with `S`'s own state types.
fn validate_payloads<S: AsmSpec>(state: &AnchorState) -> AsmResult<()> {
    let mut stage = PayloadValidationStage { state, error: None };
    S::call_subprotocols(&mut stage);
    match stage.error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Collects `(id, codec version)` for each invoked subprotocol.
#[derive(Default)]
struct SchemaStage {
    schema: Vec<SectionSchema>,
}

impl Stage for SchemaStage {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        self.schema
            .push(SectionSchema::new(S::ID, S::STATE_VERSION));
    }
}

/// Decodes each declared section, recording the first failure.
///
/// A `Stage` walk is infallible, so the error is carried out in a field rather
/// than returned.
struct PayloadValidationStage<'a> {
    state: &'a AnchorState,
    error: Option<AsmError>,
}

impl Stage for PayloadValidationStage<'_> {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        if self.error.is_some() {
            return;
        }

        let Some(section) = self.state.find_section(S::ID) else {
            // Schema validation runs first and would have caught this; keep a
            // real error rather than a panic in case a caller reorders them.
            self.error = Some(AsmError::InvalidSubprotocolState(S::ID));
            return;
        };

        if let Err(error) = section.verify_canonical::<S>() {
            self.error = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use ssz::Encode;
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::L1BlockCommitment;
    use strata_l1_txfmt::MagicBytes;

    use super::*;
    use crate::{
        ANCHOR_STATE_VERSION, AsmHistoryAccumulatorState, ChainViewState, HeaderVerificationState,
        MsgRelayer, NullMsg, SectionState, StateValidationError, SubprotocolId, TxInputRef,
        VerifiedAuxData,
    };

    const ID: SubprotocolId = 7;

    /// Two versions of one subprotocol. They share a state type, so the older
    /// version's bytes decode perfectly well under the newer one — only the
    /// declared codec version separates them, which is exactly the situation a
    /// migration has to resolve.
    macro_rules! subproto {
        ($name:ident, $version:expr) => {
            struct $name;

            impl Subprotocol for $name {
                const ID: SubprotocolId = ID;
                const STATE_VERSION: u8 = $version;
                type InitConfig = ();
                type State = u64;
                type Msg = NullMsg<ID>;

                fn init(_config: &Self::InitConfig) -> Self::State {
                    0
                }

                fn process_txs(
                    _state: &mut Self::State,
                    _txs: &[TxInputRef<'_>],
                    _header_vs: &HeaderVerificationState,
                    _verified_aux_data: &VerifiedAuxData,
                    _relayer: &mut impl MsgRelayer,
                ) {
                }

                fn process_msgs(
                    _state: &mut Self::State,
                    _msgs: &[Self::Msg],
                    _l1ref: &L1BlockCommitment,
                ) {
                }
            }
        };
    }

    subproto!(SubprotoV0, 0);
    subproto!(SubprotoV1, 1);

    /// The released specification: no predecessor, so no migration into it.
    struct SpecV0;

    impl AsmSpec for SpecV0 {
        const ID: AsmSpecId = AsmSpecId::V0;

        fn call_subprotocols(stage: &mut impl Stage) {
            stage.invoke_subprotocol::<SubprotoV0>();
        }
    }

    /// The successor. Its migration doubles the section value so the test can
    /// tell a migrated state from a passed-through one.
    struct SpecV1;

    impl AsmSpec for SpecV1 {
        const ID: AsmSpecId = AsmSpecId::V1;

        fn call_subprotocols(stage: &mut impl Stage) {
            stage.invoke_subprotocol::<SubprotoV1>();
        }

        fn predecessor() -> Option<AsmSpecPredecessor> {
            Some(AsmSpecPredecessor::of::<SpecV0>())
        }

        fn migrate_state(pre_state: &AnchorState) -> AsmResult<AnchorState> {
            let old = pre_state
                .find_section(ID)
                .expect("predecessor section")
                .try_to_state::<SubprotoV0>()?;
            Ok(rebuild(
                pre_state,
                SectionState::from_state::<SubprotoV1>(&(old * 2))?,
            ))
        }
    }

    /// A broken successor: its migration emits the predecessor's codec version,
    /// so the state it produces cannot be loaded by its own pipeline.
    struct BrokenSpecV1;

    impl AsmSpec for BrokenSpecV1 {
        const ID: AsmSpecId = AsmSpecId::V1;

        fn call_subprotocols(stage: &mut impl Stage) {
            stage.invoke_subprotocol::<SubprotoV1>();
        }

        fn predecessor() -> Option<AsmSpecPredecessor> {
            Some(AsmSpecPredecessor::of::<SpecV0>())
        }

        fn migrate_state(pre_state: &AnchorState) -> AsmResult<AnchorState> {
            let old = pre_state
                .find_section(ID)
                .expect("predecessor section")
                .try_to_state::<SubprotoV0>()?;
            // Still stamped at V0's codec version.
            Ok(rebuild(
                pre_state,
                SectionState::from_state::<SubprotoV0>(&old)?,
            ))
        }
    }

    fn rebuild(template: &AnchorState, section: SectionState) -> AnchorState {
        AnchorState {
            version: template.version,
            magic: template.magic,
            chain_view: template.chain_view.clone(),
            sections: vec![section].try_into().expect("one section fits"),
        }
    }

    fn state_with(section: SectionState) -> AnchorState {
        let anchor = L1Anchor {
            block: L1BlockCommitment::default(),
            next_target: 0x1d00ffff,
            epoch_start_timestamp: 1_231_006_505,
            network: Network::Signet,
        };
        AnchorState {
            version: ANCHOR_STATE_VERSION,
            magic: AnchorState::magic_ssz(MagicBytes::new(*b"ALPN")),
            chain_view: ChainViewState {
                pow_state: HeaderVerificationState::init(anchor),
                history_accumulator: AsmHistoryAccumulatorState::new(0),
            },
            sections: vec![section].try_into().expect("one section fits"),
        }
    }

    fn v0_state(value: u64) -> AnchorState {
        state_with(SectionState::from_state::<SubprotoV0>(&value).expect("fits"))
    }

    fn v1_state(value: u64) -> AnchorState {
        state_with(SectionState::from_state::<SubprotoV1>(&value).expect("fits"))
    }

    fn state_at_version(version: u8, value: u64) -> AnchorState {
        state_with(SectionState::new(ID, version, value.as_ssz_bytes()).expect("fits"))
    }

    /// The schema is derived from the pipeline, so it cannot drift from the
    /// subprotocols a spec actually invokes.
    #[test]
    fn schema_comes_from_the_declared_pipeline() {
        assert_eq!(section_schema::<SpecV0>(), vec![SectionSchema::new(ID, 0)]);
        assert_eq!(section_schema::<SpecV1>(), vec![SectionSchema::new(ID, 1)]);
    }

    /// Steady path: state already at the spec's schema is borrowed, never
    /// migrated and never cloned.
    #[test]
    fn matching_state_is_passed_through_by_reference() {
        let state = v0_state(21);
        let prepared = prepare_state::<SpecV0>(&state).expect("prepares");

        assert!(!prepared.was_migrated());
        assert_eq!(prepared.state(), &state);
    }

    /// Boundary block: the predecessor's state is converted, and the framework
    /// hands back the migrated value for the whole transition to observe.
    #[test]
    fn predecessor_state_is_migrated_for_the_successor() {
        let state = v0_state(21);
        let prepared = prepare_state::<SpecV1>(&state).expect("migrates");

        assert!(prepared.was_migrated());
        let section = prepared.state().find_section(ID).expect("section");
        assert_eq!(section.version, SubprotoV1::STATE_VERSION);
        assert_eq!(section.try_to_state::<SubprotoV1>().expect("decodes"), 42);
    }

    /// A schema mismatch is not by itself evidence that migration is valid.
    /// The input must be the successor's exact direct predecessor, otherwise a
    /// future or partially migrated state could be interpreted as the old
    /// layout.
    #[test]
    fn state_outside_the_declared_predecessor_is_not_migrated() {
        let state = state_at_version(2, 21);
        let err = prepare_state::<SpecV1>(&state).expect_err("version 2 is not the predecessor");

        assert!(
            matches!(
                err,
                AsmError::MigrationInputRejected {
                    into: AsmSpecId::V1,
                    source: StateValidationError::SectionVersionMismatch {
                        id: ID,
                        expected: 0,
                        actual: 2,
                    },
                }
            ),
            "expected the predecessor schema violation, got {err:?}",
        );
    }

    /// The block *after* the boundary must not migrate again. Nothing tracks
    /// whether a migration has run; the state's own codec versions answer it,
    /// which is what makes re-running a block safe.
    #[test]
    fn migration_does_not_run_twice() {
        let state = v0_state(21);
        let migrated = prepare_state::<SpecV1>(&state)
            .expect("migrates")
            .into_owned();

        let again = prepare_state::<SpecV1>(&migrated).expect("prepares");
        assert!(!again.was_migrated(), "already at this spec's schema");
        assert_eq!(
            again
                .state()
                .find_section(ID)
                .expect("section")
                .try_to_state::<SubprotoV1>()
                .expect("decodes"),
            42,
            "value must not be doubled a second time",
        );
    }

    /// The framework does not trust a migration's output: it must satisfy the
    /// target spec's schema, or the boundary fails instead of committing state
    /// the pipeline could never load.
    #[test]
    fn migration_output_is_verified_against_the_target_schema() {
        let state = v0_state(21);
        let err = prepare_state::<BrokenSpecV1>(&state)
            .expect_err("output is at the wrong codec version");

        assert!(
            matches!(
                err,
                AsmError::MigrationOutputRejected {
                    into: AsmSpecId::V1,
                    source: StateValidationError::SectionVersionMismatch {
                        id: ID,
                        expected: 1,
                        actual: 0,
                    },
                }
            ),
            "expected the schema violation to be reported, got {err:?}",
        );
    }

    /// The first specification has no predecessor, so state that is not already
    /// its own is simply not executable under it.
    #[test]
    fn first_spec_defines_no_migration() {
        let state = v1_state(1);
        let err = prepare_state::<SpecV0>(&state).expect_err("no migration into v0");

        assert!(
            matches!(
                err,
                AsmError::NoMigrationDefined {
                    into: AsmSpecId::V0
                }
            ),
            "expected NoMigrationDefined, got {err:?}",
        );
    }

    /// Structural problems are reported as themselves rather than being taken
    /// for "belongs to another spec" and sent down the migration path.
    #[test]
    fn structural_failures_are_not_mistaken_for_a_boundary() {
        let mut state = v0_state(1);
        state.version = ANCHOR_STATE_VERSION.wrapping_add(1);

        let err = prepare_state::<SpecV1>(&state).expect_err("unsupported container version");
        assert!(
            matches!(
                err,
                AsmError::StateValidation(StateValidationError::UnsupportedAnchorVersion { .. })
            ),
            "expected the container version error, got {err:?}",
        );
    }

    /// Full validation additionally decodes payloads and rejects a section that
    /// is not the canonical encoding of its own value.
    #[test]
    fn validate_state_for_spec_checks_payload_canonicality() {
        let state = v0_state(21);
        assert!(validate_state_for_spec::<SpecV0>(&state).is_ok());

        let mut data = 21u64.as_ssz_bytes();
        data.push(0);
        let bloated = state_with(SectionState::new(ID, 0, data).expect("fits"));
        assert!(
            validate_state_for_spec::<SpecV0>(&bloated).is_err(),
            "a non-canonical payload must be rejected",
        );
    }
}
