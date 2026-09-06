//! The Strata ASM specifications: one per set of consensus rules.
//!
//! Each specification is target-fixed. [`StrataAsmSpecV0`] is the rules as
//! released in `v0.3.0-rc.2`, kept executable so the blocks it governed can
//! still be replayed; [`StrataAsmSpecV1`] is the current rules, reached by the
//! migration on this module's boundary.
//!
//! Adding a specification means adding a type here and, if any section's layout
//! changed, a `migrate_state`. Every earlier specification keeps its place: a
//! node replaying history executes them all.

use strata_asm_common::{
    AnchorState, AsmError, AsmResult, AsmSpec, AsmSpecId, AsmSpecPredecessor, SectionState,
    SectionStateExt, Stage, Subprotocol,
};
// Current (v1) pipeline.
use strata_asm_proto_admin::{AdministrationSubprotocol, migrate_from_v0 as migrate_admin};
// Released (v0) pipeline.
use strata_asm_proto_admin_v0::AdministrationSubprotocol as AdministrationSubprotocolV0;
use strata_asm_proto_bridge::BridgeSubprotoV1;
use strata_asm_proto_bridge_v0::BridgeV1Subproto as BridgeSubprotocolV0;
use strata_asm_proto_checkpoint::CheckpointSubprotocol;
use strata_asm_proto_checkpoint_v0::CheckpointSubprotocolV0;
use strata_checkpoint_verification::migrate_from_v0 as migrate_checkpoint;

/// The Strata ASM rules as released in `v0.3.0-rc.2`.
///
/// The first specification, so nothing migrates into it: state that is not
/// already its own does not belong to it.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrataAsmSpecV0;

impl AsmSpec for StrataAsmSpecV0 {
    const ID: AsmSpecId = AsmSpecId::V0;

    fn call_subprotocols(stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocolV0>();
        stage.invoke_subprotocol::<CheckpointSubprotocolV0>();
        stage.invoke_subprotocol::<BridgeSubprotocolV0>();
    }
}

/// The current Strata ASM rules.
///
/// Same subprotocols, in the same order, at the same ids — a version swap moves
/// no state and reorders no section. What differs is each subprotocol's
/// behaviour, and for two of them its state layout.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrataAsmSpecV1;

impl AsmSpec for StrataAsmSpecV1 {
    const ID: AsmSpecId = AsmSpecId::V1;

    fn call_subprotocols(stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeSubprotoV1>();
    }

    fn predecessor() -> Option<AsmSpecPredecessor> {
        Some(AsmSpecPredecessor::of::<StrataAsmSpecV0>())
    }

    /// Converts released state into this specification's layout.
    ///
    /// Two of the three sections change layout and one does not, which is the
    /// whole reason a section's codec version is per-subprotocol rather than
    /// per-spec:
    ///
    /// - **administration** appends `ol_transition_pending`. The container holds variable-size
    ///   fields, so a new fixed-size field enlarges the fixed part and shifts every offset.
    /// - **checkpoint** inserts `pending_transition` mid-container, shifting everything after it.
    /// - **bridge** is unchanged. Every encoded struct in its state was verified identical against
    ///   the release tag, so its section carries across untouched at the same codec version — there
    ///   is nothing to convert, and inventing a conversion would only add a way to get it wrong.
    ///
    /// The framework verifies the result against this specification's schema and
    /// decodes every payload, so a mistake here fails at the boundary rather
    /// than committing state the pipeline could not load.
    fn migrate_state(pre_state: &AnchorState) -> AsmResult<AnchorState> {
        let admin = migrate_admin(
            &section::<AdministrationSubprotocolV0>(pre_state)?,
            pre_state.last_processed_block().height(),
        )
        .map_err(|error| AsmError::MigrationFailed {
            id: AdministrationSubprotocol::ID,
            reason: error.to_string(),
        })?;

        let checkpoint = migrate_checkpoint(&section::<CheckpointSubprotocolV0>(pre_state)?)
            .map_err(|error| AsmError::MigrationFailed {
                id: CheckpointSubprotocol::ID,
                reason: error.to_string(),
            })?;

        // Carried byte-for-byte: same layout, same codec version.
        let bridge = pre_state
            .find_section(BridgeSubprotoV1::ID)
            .ok_or(AsmError::InvalidSubprotocolState(BridgeSubprotoV1::ID))?
            .clone();

        let mut sections = vec![
            SectionState::from_state::<AdministrationSubprotocol>(&admin)?,
            SectionState::from_state::<CheckpointSubprotocol>(&checkpoint)?,
            bridge,
        ];
        // The section list is canonically ordered by subprotocol id.
        sections.sort_by_key(|section| section.id);

        Ok(AnchorState {
            version: pre_state.version,
            magic: pre_state.magic,
            chain_view: pre_state.chain_view.clone(),
            sections: sections.try_into().map_err(AsmError::TooManySections)?,
        })
    }
}

/// Decodes the section `S` owns from `state`.
fn section<S: Subprotocol>(state: &AnchorState) -> AsmResult<S::State> {
    state
        .find_section(S::ID)
        .ok_or(AsmError::InvalidSubprotocolState(S::ID))?
        .try_to_state::<S>()
}

#[cfg(test)]
mod tests {
    use strata_asm_common::{SectionSchema, section_schema};

    use super::*;

    /// The two specifications route the same subprotocols at the same ids, so a
    /// version swap moves no state and reorders no section.
    #[test]
    fn both_specs_route_the_same_ids_in_the_same_order() {
        let v0: Vec<_> = section_schema::<StrataAsmSpecV0>()
            .iter()
            .map(|entry| entry.id())
            .collect();
        let v1: Vec<_> = section_schema::<StrataAsmSpecV1>()
            .iter()
            .map(|entry| entry.id())
            .collect();

        assert_eq!(v0, v1);
    }

    /// The schemas must differ, or `prepare_state` could not tell state that
    /// needs migrating from state that does not. They differ in exactly the two
    /// sections whose layouts changed.
    #[test]
    fn the_schemas_differ_in_exactly_the_changed_sections() {
        let v0 = section_schema::<StrataAsmSpecV0>();
        let v1 = section_schema::<StrataAsmSpecV1>();

        assert_ne!(v0, v1, "the schemas must discriminate the two specs");

        let changed: Vec<_> = v0
            .iter()
            .zip(v1.iter())
            .filter(|(a, b)| a.version() != b.version())
            .map(|(a, _)| a.id())
            .collect();

        assert_eq!(
            changed,
            vec![AdministrationSubprotocol::ID, CheckpointSubprotocol::ID],
            "only administration and checkpoint changed layout; bridge did not",
        );
    }

    /// Bridge keeps its codec version across the boundary, which is what makes
    /// carrying its section byte-for-byte correct.
    #[test]
    fn bridge_keeps_its_codec_version() {
        assert_eq!(
            BridgeSubprotocolV0::STATE_VERSION,
            BridgeSubprotoV1::STATE_VERSION,
        );
        assert!(
            section_schema::<StrataAsmSpecV1>().contains(&SectionSchema::new(
                BridgeSubprotoV1::ID,
                BridgeSubprotocolV0::STATE_VERSION
            )),
        );
    }

    /// The migration boundary accepts one exact source schema: the released
    /// specification immediately before the current one.
    #[test]
    fn successor_declares_the_released_schema_as_its_predecessor() {
        assert_eq!(
            StrataAsmSpecV1::predecessor(),
            Some(AsmSpecPredecessor::of::<StrataAsmSpecV0>()),
        );
    }
}
