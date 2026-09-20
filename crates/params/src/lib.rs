//! Configuration parameters for the Anchor State Machine (ASM).
//!
//! Provides [`AsmParams`], which bundles the L1 magic bytes, genesis L1 view,
//! and the list of active [`SubprotocolInstance`]s needed to initialize and
//! run an ASM instance. The per-subprotocol configurations are defined in each
//! subprotocol's own types crate and only aggregated (and re-exported) here.
//!
//! [`AsmParams::verify`] covers what no single configuration can check on its own; see the
//! `verification` module.

mod params;
#[cfg(test)]
mod test_fixtures;
mod verification;

pub use params::{AsmParams, SubprotocolInstance};
pub use strata_asm_admin_types::AdministrationInitConfig;
pub use strata_asm_bridge_types::BridgeInitConfig;
pub use strata_asm_checkpoint_types::CheckpointInitConfig;
pub use verification::InvalidAsmParams;
