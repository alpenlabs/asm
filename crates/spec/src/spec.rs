//! Strata ASM specification defining the subprotocol pipeline.

use strata_asm_common::{AnchorState, AsmSpec, SpecId, Stage};
use strata_asm_params::AsmParams;
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge::BridgeSubprotoV1;
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

    fn prepare(&self, state: &AnchorState) -> AnchorState {
        assert_eq!(state.spec_id, Self::ID, "unsupported source spec");
        state.clone()
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
