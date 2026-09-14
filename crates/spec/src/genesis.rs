//! Genesis anchor state construction from [`StrataGenesisConfig`].
//!
//! A chain can be launched under either specification. A deployment that must
//! replay history already written under the released rules starts from
//! [`construct_v0_genesis_state`] and reaches the successor through the upgrade
//! boundary; a fresh chain with no such history starts from
//! [`construct_v1_genesis_state`] and never migrates.
//!
//! Both build the same chain view and the same section order. They differ only
//! in which specification's state types fill the sections, and therefore in the
//! codec versions those sections are stamped with.

use strata_asm_common::{
    ANCHOR_STATE_VERSION, AnchorState, AsmBootstrap, AsmHistoryAccumulatorState, BootstrapError,
    ChainViewState, HeaderVerificationState, SectionState, SectionStateExt,
};
use strata_asm_params::StrataGenesisConfig;

use crate::spec::{StrataAsmSpecV0, StrataAsmSpecV1};

/// Builds the released specification's genesis state and validates it for that
/// specification.
///
/// The worker takes an [`AsmBootstrap`] rather than a bare state, so whoever
/// holds the params proves here that the state is executable before the worker
/// writes anything.
pub fn build_v0_bootstrap(config: &StrataGenesisConfig) -> Result<AsmBootstrap, BootstrapError> {
    AsmBootstrap::try_new::<StrataAsmSpecV0>(construct_v0_genesis_state(config))
}

/// Builds the successor specification's genesis state and validates it for that
/// specification.
pub fn build_v1_bootstrap(config: &StrataGenesisConfig) -> Result<AsmBootstrap, BootstrapError> {
    AsmBootstrap::try_new::<StrataAsmSpecV1>(construct_v1_genesis_state(config))
}

/// Builds the genesis [`AnchorState`] under the released specification.
///
/// Used by a chain that has L1 history written under the released rules: its
/// genesis state must be one the released rules can execute, so the upgrade
/// boundary has a predecessor to migrate from.
pub fn construct_v0_genesis_state(config: &StrataGenesisConfig) -> AnchorState {
    use strata_asm_proto_admin_v0::{AdministrationSubprotoState, AdministrationSubprotocol};
    use strata_asm_proto_bridge_v0::{BridgeV1State, BridgeV1Subproto};
    use strata_asm_proto_checkpoint_v0::CheckpointSubprotocolV0;
    use strata_checkpoint_verification_v0::CheckpointState;

    let admin = SectionState::from_state::<AdministrationSubprotocol>(
        &AdministrationSubprotoState::new(&config.admin),
    )
    .expect("asm: Admin v0 genesis state fits section data capacity");

    let checkpoint = SectionState::from_state::<CheckpointSubprotocolV0>(&CheckpointState::init(
        config.checkpoint.clone(),
    ))
    .expect("asm: Checkpoint v0 genesis state fits section data capacity");

    let bridge = SectionState::from_state::<BridgeV1Subproto>(&BridgeV1State::new(&config.bridge))
        .expect("asm: Bridge v0 genesis state fits section data capacity");

    assemble(config, admin, checkpoint, bridge)
}

/// Builds the genesis [`AnchorState`] under the successor specification.
///
/// Used by a chain launched directly on the successor rules. It has no
/// predecessor state and never crosses the upgrade boundary.
pub fn construct_v1_genesis_state(config: &StrataGenesisConfig) -> AnchorState {
    use strata_asm_proto_admin::{AdministrationSubprotoState, AdministrationSubprotocol};
    use strata_asm_proto_bridge::{BridgeStateV1, BridgeSubprotoV1};
    use strata_asm_proto_checkpoint::{CheckpointState, CheckpointSubprotocol};

    let admin = SectionState::from_state::<AdministrationSubprotocol>(
        &AdministrationSubprotoState::new(&config.admin),
    )
    .expect("asm: Admin genesis state fits section data capacity");

    let checkpoint = SectionState::from_state::<CheckpointSubprotocol>(&CheckpointState::init(
        config.checkpoint.clone(),
    ))
    .expect("asm: Checkpoint genesis state fits section data capacity");

    let bridge = SectionState::from_state::<BridgeSubprotoV1>(&BridgeStateV1::new(&config.bridge))
        .expect("asm: Bridge genesis state fits section data capacity");

    assemble(config, admin, checkpoint, bridge)
}

/// Assembles the chain view and section list shared by both specifications.
///
/// Sections are listed in subprotocol-id order, which is the canonical order the
/// state envelope is validated against.
fn assemble(
    config: &StrataGenesisConfig,
    admin: SectionState,
    checkpoint: SectionState,
    bridge: SectionState,
) -> AnchorState {
    let history_accumulator = AsmHistoryAccumulatorState::new(config.anchor.block.height() as u64);
    let chain_view = ChainViewState {
        history_accumulator,
        pow_state: HeaderVerificationState::init(config.anchor.clone()),
    };

    AnchorState {
        version: ANCHOR_STATE_VERSION,
        magic: AnchorState::magic_ssz(config.magic),
        chain_view,
        sections: vec![admin, checkpoint, bridge]
            .try_into()
            .expect("asm: genesis sections fit within capacity"),
    }
}
