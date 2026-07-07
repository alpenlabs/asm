//! Strata ASM specification defining the subprotocol pipeline.

use strata_asm_common::{AnchorState, AsmSpec, Stage};
use strata_asm_params::GenesisParams;
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge_v1::BridgeV1Subproto;
use strata_asm_proto_checkpoint::CheckpointSubprotocol;

/// Strata ASM specification.
///
/// Declares which subprotocols participate in the ASM and the order in which
/// they are invoked. The same ordering is used for every execution stage
/// (load, preprocess, process, finish).
#[derive(Debug)]
pub struct StrataAsmSpec;

impl AsmSpec for StrataAsmSpec {
    type Params = GenesisParams;

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeV1Subproto>();
    }

    fn construct_genesis_state(&self, params: &Self::Params) -> AnchorState {
        crate::construct_genesis_state(params)
    }

    fn genesis_l1_height(&self, params: &Self::Params) -> u64 {
        params.anchor.block.height() as u64
    }
}
