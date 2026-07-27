//! Configuration parameters for the Anchor State Machine (ASM).
//!
//! Provides [`AsmParams`], which bundles the L1 magic bytes, genesis L1 view,
//! and the list of active [`SubprotocolInstance`]s needed to initialize and
//! run an ASM instance. The per-subprotocol configurations are defined in each
//! subprotocol's own types crate and only aggregated (and re-exported) here.

mod params;

pub use params::{AsmParams, SubprotocolInstance};
pub use strata_asm_admin_types::AdministrationInitConfig;
pub use strata_asm_proto_bridge_types::BridgeInitConfig;
pub use strata_asm_proto_checkpoint_types::CheckpointInitConfig;
