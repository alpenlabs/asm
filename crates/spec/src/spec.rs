//! Strata ASM specification defining the subprotocol pipeline.

use strata_asm_common::{AnchorState, AsmSpec, StfParams};
use strata_asm_params::AsmParams;
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge_v1::BridgeV1Subproto;
use strata_asm_proto_checkpoint::CheckpointSubprotocol;

use crate::genesis;

/// Strata ASM specification.
///
/// Declares which subprotocols participate in the ASM and the order in which
/// they are invoked. The same ordering is used for every execution stage
/// (load, preprocess, process, finish).
#[derive(Debug)]
pub struct StrataAsmSpec;

impl AsmSpec for StrataAsmSpec {
    type Subprotocols = (
        AdministrationSubprotocol,
        CheckpointSubprotocol,
        BridgeV1Subproto,
    );

    type Params = AsmParams;

    fn construct_genesis_state(params: &AsmParams) -> AnchorState {
        genesis::construct_genesis_state(&params.genesis)
    }

    fn stf_params(params: &AsmParams) -> StfParams {
        params.stf.stf_params()
    }
}
