//! Strata ASM specification defining the subprotocol pipeline.

use strata_asm_common::{AnchorState, AsmResult, AsmSpec, SpecId, Stage, Subprotocol};
use strata_asm_params::AsmParams;
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge::{
    BridgeSubprotoV1, BridgeSubprotoV2, BridgeSubprotoV3, migrate_bridge_section,
};
use strata_asm_proto_checkpoint::CheckpointSubprotocol;

/// Strata ASM specification.
///
/// Declares which subprotocols participate in the ASM and the order in which
/// they are invoked. The same ordering is used for every execution stage
/// (load, preprocess, process, finish).
#[derive(Debug)]
pub struct StrataAsmSpec;

impl AsmSpec for StrataAsmSpec {
    const ID: SpecId = 0;

    type GenesisParams = AsmParams;

    fn prepare(&self, state: &AnchorState) -> AsmResult<AnchorState> {
        assert_eq!(state.spec_id, Self::ID, "unsupported source spec");
        Ok(state.clone())
    }

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeSubprotoV1>();
    }

    fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState {
        crate::construct_genesis_state(params)
    }

    fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64 {
        params.anchor.block.height() as u64
    }
}

/// Strata ASM specification, revision 1.
///
/// Identical to [`StrataAsmSpec`] except that the bridge commits `OperatorClaimUnlockV1` export
/// leaves, naming the fulfillment's assignee by MuSig2 public key instead of by operator table
/// index. That moves every leaf committed after activation, and the bridge export container's
/// MMR root with it, which is why it is a separate ruleset rather than an edit to spec 0.
///
/// Nothing else moves. The bridge keeps its subprotocol ID and section schema version, so
/// [`prepare`](AsmSpec::prepare) carries sections across unchanged and there is no migration.
#[derive(Debug)]
pub struct StrataAsmSpecV1;

impl AsmSpec for StrataAsmSpecV1 {
    const ID: SpecId = 1;

    type GenesisParams = AsmParams;

    fn prepare(&self, state: &AnchorState) -> AsmResult<AnchorState> {
        assert!(
            matches!(state.spec_id, StrataAsmSpec::ID | Self::ID),
            "unsupported source spec"
        );
        let mut prepared = state.clone();
        prepared.spec_id = Self::ID;
        Ok(prepared)
    }

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeSubprotoV2>();
    }

    fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState {
        // Sections are keyed by subprotocol ID and schema version, both unchanged from spec 0,
        // so only the ruleset identity differs from spec 0's genesis.
        let mut state = crate::construct_genesis_state(params);
        state.spec_id = Self::ID;
        state
    }

    fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64 {
        params.anchor.block.height() as u64
    }
}

/// Strata ASM specification, revision 2.
///
/// Identical to [`StrataAsmSpecV1`] except that the bridge runs [`BridgeSubprotoV3`]. When no
/// active operator from a deposit's notary set can take an expired withdrawal assignment, earlier
/// rulesets halt block processing; this one marks the assignment unassignable and continues.
/// Recording that status moves the bridge section to schema 1, which earlier rulesets cannot
/// read, so it is a separate ruleset rather than an edit to spec 0 or spec 1.
///
/// [`prepare`](AsmSpec::prepare) migrates the bridge section of a spec 0 or spec 1 parent from
/// schema 0 to schema 1, with every existing assignment active. Other sections carry across
/// unchanged.
#[derive(Debug)]
pub struct StrataAsmSpecV2;

impl AsmSpec for StrataAsmSpecV2 {
    const ID: SpecId = 2;

    type GenesisParams = AsmParams;

    fn prepare(&self, state: &AnchorState) -> AsmResult<AnchorState> {
        let mut prepared = state.clone();
        match state.spec_id {
            Self::ID => {}
            StrataAsmSpec::ID | StrataAsmSpecV1::ID => {
                migrate_sections(&mut prepared)?;
                prepared.spec_id = Self::ID;
            }
            other => panic!("unsupported source spec {other}"),
        }
        Ok(prepared)
    }

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeSubprotoV3>();
    }

    fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState {
        // Spec 0's genesis bridge holds no assignments, so its schema-1 section is the same state
        // in the new layout. Building it by migration keeps genesis equal to what an upgraded
        // chain would hold.
        let mut state = crate::construct_genesis_state(params);
        migrate_sections(&mut state).expect("genesis bridge section migrates to schema 1");
        state.spec_id = Self::ID;
        state
    }

    fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64 {
        params.anchor.block.height() as u64
    }
}

/// Migrates a spec 0 or spec 1 state's sections to the schemas spec 2 reads.
///
/// Only the bridge section changes schema.
///
/// # Errors
///
/// Returns an error if the bridge section does not decode under schema 0 or does not fit its
/// capacity after migration.
///
/// # Panics
///
/// Panics if the state has no bridge section.
fn migrate_sections(state: &mut AnchorState) -> AsmResult<()> {
    let bridge = state
        .sections
        .iter_mut()
        .find(|section| section.id == BridgeSubprotoV3::ID)
        .expect("supported source has a bridge section");
    migrate_bridge_section(bridge)
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{AsmError, SectionState, SectionStateExt};
    use strata_asm_params::AsmParams;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    fn bridge_section(state: &AnchorState) -> &SectionState {
        state
            .find_section(BridgeSubprotoV1::ID)
            .expect("state has a bridge section")
    }

    fn arbitrary_params() -> AsmParams {
        ArbitraryGenerator::new().generate()
    }

    /// Specs 0 and 1 keep the bridge at schema 0 and carry the parent's sections untouched.
    #[test]
    fn specs_0_and_1_keep_the_schema_0_bridge_section() {
        let params = arbitrary_params();
        let genesis = StrataAsmSpec.construct_genesis_state(&params);
        assert_eq!(bridge_section(&genesis).version, 0);

        assert_eq!(StrataAsmSpec.prepare(&genesis).unwrap(), genesis);

        let prepared = StrataAsmSpecV1.prepare(&genesis).unwrap();
        assert_eq!(prepared.sections, genesis.sections);
        assert_eq!(prepared.spec_id, StrataAsmSpecV1::ID);
        assert_eq!(
            StrataAsmSpecV1.construct_genesis_state(&params).sections,
            genesis.sections
        );
    }

    /// Spec 2 upgrades a spec 0 or spec 1 parent's bridge section to schema 1 and leaves the
    /// other sections as they were.
    #[test]
    fn spec_2_prepare_migrates_spec_0_and_spec_1_parents() {
        let params = arbitrary_params();
        let spec_0 = StrataAsmSpec.construct_genesis_state(&params);
        let spec_1 = StrataAsmSpecV1.construct_genesis_state(&params);

        for source in [&spec_0, &spec_1] {
            let prepared = StrataAsmSpecV2.prepare(source).unwrap();
            assert_eq!(prepared.spec_id, StrataAsmSpecV2::ID);
            let bridge = bridge_section(&prepared);
            assert_eq!(bridge.version, BridgeSubprotoV3::STATE_VERSION);
            bridge
                .try_to_state::<BridgeSubprotoV3>()
                .expect("migrated bridge section loads under spec 2");
            for (before, after) in source.sections.iter().zip(prepared.sections.iter()) {
                if before.id != BridgeSubprotoV3::ID {
                    assert_eq!(before, after);
                }
            }
        }
    }

    /// Spec 2's genesis is spec 0's genesis upgraded, so a fresh spec 2 chain and an upgraded one
    /// start from the same sections, and its own states pass through `prepare` unchanged.
    #[test]
    fn spec_2_genesis_matches_an_upgraded_spec_0_genesis() {
        let params = arbitrary_params();
        let genesis = StrataAsmSpecV2.construct_genesis_state(&params);
        let upgraded = StrataAsmSpecV2
            .prepare(&StrataAsmSpec.construct_genesis_state(&params))
            .unwrap();

        assert_eq!(genesis, upgraded);
        assert_eq!(StrataAsmSpecV2.prepare(&genesis).unwrap(), genesis);
    }

    /// A spec 2 parent whose bridge section is still at schema 0 is not migrated again; the
    /// loader rejects it instead of `prepare` repairing it silently.
    #[test]
    fn spec_2_prepare_does_not_migrate_its_own_states() {
        let mut source = StrataAsmSpec.construct_genesis_state(&arbitrary_params());
        source.spec_id = StrataAsmSpecV2::ID;

        let prepared = StrataAsmSpecV2.prepare(&source).unwrap();
        assert_eq!(prepared, source);
        assert!(
            bridge_section(&prepared)
                .try_to_state::<BridgeSubprotoV3>()
                .is_err()
        );
    }

    /// A bridge section the migration cannot read fails `prepare` with an error rather than a
    /// panic, so the worker reports the block instead of aborting.
    #[test]
    fn spec_2_prepare_returns_migration_errors() {
        let mut source = StrataAsmSpec.construct_genesis_state(&arbitrary_params());
        let bridge = source
            .sections
            .iter_mut()
            .find(|section| section.id == BridgeSubprotoV1::ID)
            .expect("genesis has a bridge section");
        *bridge = SectionState::new(bridge.id, bridge.version, vec![0xff; 3])
            .expect("small section fits");

        assert!(matches!(
            StrataAsmSpecV2.prepare(&source),
            Err(AsmError::Deserialization(id, _)) if id == BridgeSubprotoV1::ID
        ));
    }

    #[test]
    #[should_panic(expected = "unsupported source spec")]
    fn spec_2_prepare_rejects_unknown_source_spec() {
        let mut source = StrataAsmSpec.construct_genesis_state(&arbitrary_params());
        source.spec_id = 3;
        let _ = StrataAsmSpecV2.prepare(&source);
    }
}
