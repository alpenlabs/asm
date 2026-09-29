//! Test-only successor shared by transition and running-worker qualification.

use strata_asm_common::{AnchorState, AsmSpec, SpecId, Stage};
use strata_asm_params::AsmParams;
use strata_asm_spec::{construct_genesis_state, StrataAsmSpec};

/// A test-only successor retains the subprotocol schemas and changes ruleset identity.
#[derive(Debug)]
pub struct TestSuccessor;

impl AsmSpec for TestSuccessor {
    const ID: SpecId = 17;
    type GenesisParams = AsmParams;

    fn prepare(&self, source: &AnchorState) -> AnchorState {
        assert!(matches!(source.spec_id, 0 | Self::ID));
        let mut state = source.clone();
        state.spec_id = Self::ID;
        state
    }

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        StrataAsmSpec.call_subprotocols(stage);
    }

    fn construct_genesis_state(&self, params: &AsmParams) -> AnchorState {
        let mut state = construct_genesis_state(params);
        state.spec_id = Self::ID;
        state
    }

    fn genesis_l1_height(&self, params: &AsmParams) -> u64 {
        u64::from(params.anchor.block.height())
    }
}
