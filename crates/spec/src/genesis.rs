//! Genesis anchor state construction from [`AsmParams`].

use strata_asm_common::{
    AnchorState, AsmHistoryAccumulatorState, ChainViewState, HeaderVerificationState, SectionState,
};
use strata_asm_params::AsmParams;
use strata_asm_proto_administration::{AdministrationSubprotoState, AdministrationSubprotocol};
use strata_asm_proto_bridge_v1::{BridgeV1State, BridgeV1Subproto};
use strata_asm_proto_checkpoint::{state::CheckpointState, subprotocol::CheckpointSubprotocol};
use strata_btc_verification::HeaderVerificationState as NativeHeaderVerificationState;

/// Builds the genesis [`AnchorState`] from the given [`AsmParams`].
///
/// Initialises every subprotocol's state from its config in `params` and
/// assembles the chain view (PoW header verification + history accumulator).
pub fn construct_genesis_state(params: &AsmParams) -> AnchorState {
    let genesis_admin_subprotocol_state = AdministrationSubprotoState::new(
        params
            .admin_config()
            .expect("asm: missing Admin subprotocol config in params"),
    );
    let admin_subprotocol_section =
        SectionState::from_state::<AdministrationSubprotocol>(&genesis_admin_subprotocol_state)
            .expect("asm: Admin subprotocol genesis state fits section data capacity");

    let genesis_checkpoint_subprotocol_state = CheckpointState::init(
        params
            .checkpoint_config()
            .expect("asm: missing Checkpoint subprotocol config in params")
            .clone(),
    );
    let checkpoint_subprotocol_section =
        SectionState::from_state::<CheckpointSubprotocol>(&genesis_checkpoint_subprotocol_state)
            .expect("asm: Checkpoint subprotocol genesis state fits section data capacity");

    let genesis_bridge_subprotocol_state = BridgeV1State::new(
        params
            .bridge_config()
            .expect("asm: missing Bridge subprotocol config in params"),
    );
    let bridge_subprotocol_section =
        SectionState::from_state::<BridgeV1Subproto>(&genesis_bridge_subprotocol_state)
            .expect("asm: Bridge subprotocol genesis state fits section data capacity");

    let native_header_vs = NativeHeaderVerificationState::init(params.anchor.clone());
    let history_accumulator = AsmHistoryAccumulatorState::new(params.anchor.block.height() as u64);
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
        .try_into()
        .expect("asm: genesis sections fit within capacity"),
    }
}
