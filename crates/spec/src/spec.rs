//! Strata ASM specification defining the subprotocol pipeline.

use strata_asm_common::{AnchorState, AsmSpec, AsmStfParams};
use strata_asm_params::AsmParams;
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge_v1::BridgeV1Subproto;
use strata_asm_proto_checkpoint::CheckpointSubprotocol;

use crate::genesis;

/// Strata ASM specification.
///
/// Declares which subprotocols participate in the ASM and the order in which
/// they are invoked. The same ordering is used for every execution stage
/// (load, preprocess, process, finish) and for genesis construction.
///
/// The pipeline itself is type-level (see [`AsmSpec`]); the struct exists to
/// carry the [`AsmStfParams`] through interfaces that thread a single spec value
/// (the Moho runtime). Guest programs construct it with their hardcoded
/// params — the verifying key thereby commits to them.
#[derive(Debug, Clone)]
pub struct StrataAsmSpec {
    stf_params: AsmStfParams,
}

impl StrataAsmSpec {
    /// Creates a spec executing under the given STF params.
    pub fn new(stf_params: AsmStfParams) -> Self {
        Self { stf_params }
    }

    /// Returns the STF params this executor runs under.
    pub fn stf_params(&self) -> &AsmStfParams {
        &self.stf_params
    }
}

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

    fn stf_params(params: &AsmParams) -> AsmStfParams {
        params.runtime.stf_params()
    }
}
