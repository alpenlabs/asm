//! Strata ASM specification defining the subprotocol pipeline.

use strata_asm_common::{AnchorState, AsmSpec, SpecId, Stage};
use strata_asm_params::AsmParams;
use strata_asm_proto_admin::AdministrationSubprotocol;
use strata_asm_proto_bridge::{BridgeSubprotoV1, BridgeSubprotoV2};
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

    fn prepare(&self, state: &AnchorState) -> AnchorState {
        assert!(
            matches!(state.spec_id, StrataAsmSpec::ID | Self::ID),
            "unsupported source spec"
        );
        let mut prepared = state.clone();
        prepared.spec_id = Self::ID;
        prepared
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
