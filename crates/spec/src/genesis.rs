//! Genesis anchor state construction from [`AsmParams`].

use strata_asm_common::{
    AnchorState, AsmHistoryAccumulatorState, AsmSpec, ChainViewState, HeaderVerificationState,
    SectionState, SectionStateExt,
};
use strata_asm_params::AsmParams;
use strata_asm_proto_admin::{AdministrationSubprotoState, AdministrationSubprotocol};
use strata_asm_proto_bridge::{BridgeStateV1, BridgeSubprotoV1};
use strata_asm_proto_checkpoint::{CheckpointState, CheckpointSubprotocol};

use crate::StrataAsmSpec;

/// Builds the genesis [`AnchorState`] from the given [`AsmParams`].
///
/// Initialises every subprotocol's state from its config in `params` and
/// assembles the chain view (PoW header verification + history accumulator).
///
/// # Panics
///
/// Panics if `params` lacks a subprotocol config, or if the checkpoint genesis L1 height
/// differs from the anchor height. Deserializing [`AsmParams`] rejects the latter, so it only
/// fires for parameters assembled or modified in code; [`AsmParams::set_anchor`] keeps the
/// two heights together.
pub fn construct_genesis_state(params: &AsmParams) -> AnchorState {
    let checkpoint_config = params
        .checkpoint_config()
        .expect("asm: missing Checkpoint subprotocol config in params");
    // The checkpoint tip and the manifest accumulator below must start from the same L1
    // block, or no checkpoint's coverage lines up with the accumulator.
    if let Err(mismatch) = checkpoint_config.check_genesis_l1_height(params.anchor.block.height()) {
        panic!("asm: {mismatch}");
    }

    let genesis_admin_subprotocol_state = AdministrationSubprotoState::new(
        params
            .admin_config()
            .expect("asm: missing Admin subprotocol config in params"),
    );
    let admin_subprotocol_section =
        SectionState::from_state::<AdministrationSubprotocol>(&genesis_admin_subprotocol_state)
            .expect("asm: Admin subprotocol genesis state fits section data capacity");

    let genesis_checkpoint_subprotocol_state = CheckpointState::init(checkpoint_config.clone());
    let checkpoint_subprotocol_section =
        SectionState::from_state::<CheckpointSubprotocol>(&genesis_checkpoint_subprotocol_state)
            .expect("asm: Checkpoint subprotocol genesis state fits section data capacity");

    let genesis_bridge_subprotocol_state = BridgeStateV1::new(
        params
            .bridge_config()
            .expect("asm: missing Bridge subprotocol config in params"),
    );
    let bridge_subprotocol_section =
        SectionState::from_state::<BridgeSubprotoV1>(&genesis_bridge_subprotocol_state)
            .expect("asm: Bridge subprotocol genesis state fits section data capacity");

    let history_accumulator = AsmHistoryAccumulatorState::new(params.anchor.block.height() as u64);
    let chain_view = ChainViewState {
        history_accumulator,
        pow_state: HeaderVerificationState::init(params.anchor.clone()),
    };

    AnchorState {
        spec_id: StrataAsmSpec::ID,
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

#[cfg(test)]
mod tests {
    use arbitrary::{Arbitrary, Unstructured};
    use strata_asm_params::SubprotocolInstance;

    use super::*;

    fn arbitrary_params() -> AsmParams {
        AsmParams::arbitrary(&mut Unstructured::new(&[42; 65_536])).expect("arbitrary params")
    }

    #[test]
    #[should_panic(expected = "does not match the L1 anchor height")]
    fn construct_genesis_state_rejects_a_checkpoint_height_off_the_anchor() {
        let mut params = arbitrary_params();
        for instance in &mut params.subprotocols {
            if let SubprotocolInstance::Checkpoint(config) = instance {
                config.genesis_l1_height = u32::MAX;
            }
        }

        construct_genesis_state(&params);
    }
}
