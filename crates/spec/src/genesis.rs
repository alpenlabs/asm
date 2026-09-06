//! Genesis anchor state construction from [`StrataGenesisConfig`].

use strata_asm_common::{
    AnchorState, AsmHistoryAccumulatorState, ChainViewState, HeaderVerificationState, SectionState,
    SectionStateExt,
};
use strata_asm_params::StrataGenesisConfig;
use strata_asm_proto_admin::{AdministrationSubprotoState, AdministrationSubprotocol};
use strata_asm_proto_bridge::{BridgeStateV1, BridgeSubprotoV1};
use strata_asm_proto_checkpoint::{CheckpointState, CheckpointSubprotocol};

/// Builds the genesis [`AnchorState`] from the given [`StrataGenesisConfig`].
///
/// Initialises every subprotocol's state from its named config and
/// assembles the chain view (PoW header verification + history accumulator).
pub fn construct_genesis_state(config: &StrataGenesisConfig) -> AnchorState {
    let genesis_admin_subprotocol_state = AdministrationSubprotoState::new(&config.admin);
    let admin_subprotocol_section =
        SectionState::from_state::<AdministrationSubprotocol>(&genesis_admin_subprotocol_state)
            .expect("asm: Admin subprotocol genesis state fits section data capacity");

    let genesis_checkpoint_subprotocol_state = CheckpointState::init(config.checkpoint.clone());
    let checkpoint_subprotocol_section =
        SectionState::from_state::<CheckpointSubprotocol>(&genesis_checkpoint_subprotocol_state)
            .expect("asm: Checkpoint subprotocol genesis state fits section data capacity");

    let genesis_bridge_subprotocol_state = BridgeStateV1::new(&config.bridge);
    let bridge_subprotocol_section =
        SectionState::from_state::<BridgeSubprotoV1>(&genesis_bridge_subprotocol_state)
            .expect("asm: Bridge subprotocol genesis state fits section data capacity");

    let history_accumulator = AsmHistoryAccumulatorState::new(config.anchor.block.height() as u64);
    let chain_view = ChainViewState {
        history_accumulator,
        pow_state: HeaderVerificationState::init(config.anchor.clone()),
    };

    AnchorState {
        magic: AnchorState::magic_ssz(config.magic),
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
