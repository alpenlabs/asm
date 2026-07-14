//! Genesis anchor state construction from [`AsmGenesisParams`].

use std::any::Any;

use strata_asm_common::{
    AnchorState, AsmHistoryAccumulatorState, AsmSpec, ChainViewState, HeaderVerificationState,
    SectionState, Stage, Subprotocol,
};
use strata_asm_params::{AsmGenesisParams, SubprotocolInstance};
use strata_btc_verification::HeaderVerificationState as NativeHeaderVerificationState;

use crate::StrataAsmSpec;

/// Builds the genesis [`AnchorState`] from the given [`AsmGenesisParams`].
///
/// Initialises every subprotocol's state from its config in `params` — driven
/// by the same [`AsmSpec`] subprotocol list every execution stage traverses,
/// so the pipeline and the genesis layout cannot drift apart — and assembles
/// the chain view (PoW header verification + history accumulator).
pub fn construct_genesis_state(params: &AsmGenesisParams) -> AnchorState {
    let mut stage = GenesisStateStage {
        params,
        sections: Vec::new(),
    };
    StrataAsmSpec::call_subprotocols(&mut stage);

    // Post-transition exports emit sections in ascending subprotocol-ID order
    // (see the STF's section export); genesis must produce the same layout or
    // the first transition would silently reorder the state.
    assert!(
        stage.sections.is_sorted_by_key(|s| s.id),
        "asm: genesis sections not sorted by subprotocol id"
    );

    let native_header_vs = NativeHeaderVerificationState::init(params.anchor.clone());
    let history_accumulator = AsmHistoryAccumulatorState::new(params.anchor.block.height() as u64);
    let chain_view = ChainViewState {
        history_accumulator,
        pow_state: HeaderVerificationState::from_native(native_header_vs),
    };

    AnchorState {
        magic: AnchorState::magic_ssz(params.magic),
        chain_view,
        sections: stage
            .sections
            .try_into()
            .expect("asm: genesis sections fit within capacity"),
    }
}

/// [`Stage`] that builds each subprotocol's genesis state from its config,
/// packed into its [`SectionState`] envelope.
///
/// Configs are located in the params' heterogeneous list by their type: each
/// subprotocol's `InitConfig` type appears in exactly one
/// [`SubprotocolInstance`] variant.
struct GenesisStateStage<'p> {
    params: &'p AsmGenesisParams,
    sections: Vec<SectionState>,
}

impl Stage for GenesisStateStage<'_> {
    fn invoke_subprotocol<S: Subprotocol>(&mut self) {
        let config = self
            .params
            .subprotocols
            .iter()
            .find_map(|instance| {
                let config: &dyn Any = match instance {
                    SubprotocolInstance::Admin(config) => config,
                    SubprotocolInstance::Bridge(config) => config,
                    SubprotocolInstance::Checkpoint(config) => config,
                };
                config.downcast_ref::<S::InitConfig>()
            })
            .unwrap_or_else(|| panic!("asm: missing config for subprotocol {} in params", S::ID));

        let state = S::init(config);
        let section = SectionState::from_state::<S>(&state).unwrap_or_else(|e| {
            panic!(
                "asm: genesis state for subprotocol {} exceeds section data capacity: {e}",
                S::ID
            )
        });
        self.sections.push(section);
    }
}
