//! Spec 2, which installs new administration confirmation depths when it takes over.

use strata_asm_common::{
    AnchorState, AsmSpec, SectionState, SectionStateExt, SpecId, Stage, Subprotocol,
};
use strata_asm_params::{AsmGenesisParams, ConfirmationDepths};
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge::BridgeSubprotoV2;
use strata_asm_proto_checkpoint::CheckpointSubprotocol;

use super::{StrataAsmSpec, StrataAsmSpecV1};

/// Strata ASM specification, revision 2.
///
/// Runs the same subprotocols as [`StrataAsmSpecV1`], under the administration confirmation
/// depths it carries instead of the ones the chain started with. The depths come from the
/// [`SpecV2Params`](strata_asm_params::SpecV2Params) section of the runtime params, so its guest
/// has to bake them in, and its predicate then commits to them.
///
/// [`prepare`](AsmSpec::prepare) writes the depths into the admin section when it takes over
/// from spec 0 or spec 1, and every update queued after that waits for them. Updates already in
/// the queue keep the activation height they were given.
#[derive(Debug)]
pub struct StrataAsmSpecV2(ConfirmationDepths);

impl StrataAsmSpecV2 {
    /// Creates the ruleset that installs `confirmation_depths` in the admin section.
    pub fn new(confirmation_depths: ConfirmationDepths) -> Self {
        Self(confirmation_depths)
    }
}

impl AsmSpec for StrataAsmSpecV2 {
    const ID: SpecId = 2;

    type GenesisParams = AsmGenesisParams;

    fn prepare(&self, state: &AnchorState) -> AnchorState {
        if state.spec_id == Self::ID {
            return state.clone();
        }
        assert!(
            matches!(state.spec_id, StrataAsmSpec::ID | StrataAsmSpecV1::ID),
            "unsupported source spec"
        );

        let mut prepared = state.clone();
        let section = prepared
            .sections
            .iter_mut()
            .find(|section| section.id == AdministrationSubprotocol::ID)
            .expect("supported source has an admin section");
        let mut admin = section
            .try_to_state::<AdministrationSubprotocol>()
            .expect("source admin section has the current schema");
        admin.set_confirmation_depths(self.0.clone());
        *section = SectionState::from_state::<AdministrationSubprotocol>(&admin)
            .expect("depths are fixed size, so the admin state still fits its section");
        prepared.spec_id = Self::ID;
        prepared
    }

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeSubprotoV2>();
    }

    fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState {
        // A chain that starts under spec 2 holds the same state as one that upgrades to it at
        // genesis, so the depths in the genesis admin config are replaced here too.
        self.prepare(&crate::construct_genesis_state(params))
    }

    fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64 {
        params.anchor.block.height() as u64
    }
}

#[cfg(test)]
mod tests {
    use arbitrary::{Arbitrary, Unstructured};
    use strata_asm_admin_types::UpdateTxType;
    use strata_asm_proto_admin::AdministrationSubprotoState;

    use super::*;

    fn genesis_params() -> AsmGenesisParams {
        AsmGenesisParams::arbitrary(&mut Unstructured::new(&[42; 65_536]))
            .expect("arbitrary params")
    }

    fn spec_v2_depths() -> ConfirmationDepths {
        ConfirmationDepths {
            strata_admin_multisig_update: 1,
            strata_seq_manager_multisig_update: 2,
            alpen_admin_multisig_update: 3,
            strata_security_council_multisig_update: 4,
            operator_update: 5,
            sequencer_update: 6,
            ol_stf_vk_update: 7,
            asm_stf_vk_update: 8,
            ee_stf_vk_update: 9,
            defcon3: 10,
            safe_harbor_address_update: 11,
        }
    }

    fn admin_state(state: &AnchorState) -> AdministrationSubprotoState {
        state
            .find_section(AdministrationSubprotocol::ID)
            .expect("state has an admin section")
            .try_to_state::<AdministrationSubprotocol>()
            .expect("admin section decodes")
    }

    #[test]
    fn prepare_installs_its_depths_when_taking_over_from_spec_0_or_spec_1() {
        let params = genesis_params();
        let spec = StrataAsmSpecV2::new(spec_v2_depths());

        for source in [
            StrataAsmSpec.construct_genesis_state(&params),
            StrataAsmSpecV1.construct_genesis_state(&params),
        ] {
            let source_admin = admin_state(&source);
            assert_ne!(
                source_admin.confirmation_depth(UpdateTxType::SequencerUpdate),
                Some(6),
                "the test needs depths that differ from the source"
            );

            let prepared = spec.prepare(&source);

            assert_eq!(prepared.spec_id, StrataAsmSpecV2::ID);
            let mut expected_admin = source_admin;
            expected_admin.set_confirmation_depths(spec_v2_depths());
            assert_eq!(admin_state(&prepared), expected_admin);

            // Everything outside the admin section carries across untouched.
            assert_eq!(prepared.magic, source.magic);
            assert_eq!(prepared.chain_view, source.chain_view);
            let other_sections = |state: &AnchorState| {
                state
                    .sections
                    .iter()
                    .filter(|section| section.id != AdministrationSubprotocol::ID)
                    .cloned()
                    .collect::<Vec<_>>()
            };
            assert_eq!(other_sections(&prepared), other_sections(&source));
        }
    }

    #[test]
    fn genesis_starts_with_its_depths_and_prepare_leaves_it_unchanged() {
        let spec = StrataAsmSpecV2::new(spec_v2_depths());
        let genesis = spec.construct_genesis_state(&genesis_params());

        assert_eq!(genesis.spec_id, StrataAsmSpecV2::ID);
        assert_eq!(
            admin_state(&genesis).confirmation_depth(UpdateTxType::SequencerUpdate),
            Some(6)
        );
        assert_eq!(spec.prepare(&genesis), genesis);
    }

    #[test]
    #[should_panic(expected = "unsupported source spec")]
    fn prepare_rejects_an_unknown_source_spec() {
        let mut state = StrataAsmSpec.construct_genesis_state(&genesis_params());
        state.spec_id = 3;

        StrataAsmSpecV2::new(spec_v2_depths()).prepare(&state);
    }
}
