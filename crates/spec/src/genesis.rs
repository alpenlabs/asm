use strata_asm_common::{
    AnchorState, AsmHistoryAccumulatorState, ChainViewState, HeaderVerificationState, SectionState,
};
use strata_asm_params::AsmParams;
use strata_asm_proto_administration::{AdministrationSubprotoState, AdministrationSubprotocol};
use strata_asm_proto_bridge_v1::{BridgeV1State, BridgeV1Subproto};
use strata_asm_proto_checkpoint::{state::CheckpointState, subprotocol::CheckpointSubprotocol};
use strata_btc_verification::HeaderVerificationState as NativeHeaderVerificationState;

pub fn asm_genesis(params: &AsmParams) -> AnchorState {
    let genesis_admin_subprotocol_state =
        AdministrationSubprotoState::new(params.admin_config().expect("msg"));
    let admin_subprotocol_section =
        SectionState::from_state::<AdministrationSubprotocol>(&genesis_admin_subprotocol_state);

    let genesis_checkpoint_subprotocol_state =
        CheckpointState::init(params.checkpoint_config().expect("msg").clone());
    let checkpoint_subprotocol_section =
        SectionState::from_state::<CheckpointSubprotocol>(&genesis_checkpoint_subprotocol_state);

    let genesis_bridge_subprotocol_state = BridgeV1State::new(params.bridge_config().expect("msg"));
    let bridge_subprotocol_section =
        SectionState::from_state::<BridgeV1Subproto>(&genesis_bridge_subprotocol_state);

    let native_header_vs =
        NativeHeaderVerificationState::new(params.btc_params.inner().network, &params.l1_view);
    let history_accumulator = AsmHistoryAccumulatorState::new(params.l1_view.blk.height() as u64);
    let chain_view = ChainViewState {
        history_accumulator,
        pow_state: HeaderVerificationState::from_native(native_header_vs),
    };

    AnchorState {
        magic: AnchorState::magic_ssz(params.magic),
        chain_view,
        sections: vec![
            admin_subprotocol_section,
            checkpoint_subprotocol_section,
            bridge_subprotocol_section,
        ]
        .into(),
    }
}
