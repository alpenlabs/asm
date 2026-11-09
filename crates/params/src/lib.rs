//! Configuration parameters for the Anchor State Machine (ASM).
//!
//! [`AsmParams`] is the parameter file. It has two parts:
//!
//! - [`AsmGenesisParams`] bundles the L1 magic bytes, the genesis L1 view, and the list of active
//!   [`SubprotocolInstance`]s needed to build the genesis state. The per-subprotocol configurations
//!   are defined in each subprotocol's own types crate and only aggregated (and re-exported) here.
//! - [`AsmRuntimeParams`] holds one optional section per spec after genesis, with the values that
//!   spec reads while it executes.
//!
//! Deserializing [`AsmGenesisParams`] also checks what no single configuration can check on its
//! own; see the `verification` module.
//!
//! The params file of each environment lives in this crate's `envs/` directory, named after the
//! environment. The crate's tests parse every one, so a change to the format has to convert them
//! too. `dev.json` is not a deployed chain: it is the file local builds, CI and the functional
//! tests bake into the guest, with short confirmation depths so tests run quickly.

mod genesis;
mod params;
mod runtime;
#[cfg(test)]
mod test_fixtures;
mod verification;

pub use genesis::{AsmGenesisParams, SubprotocolInstance};
pub use params::AsmParams;
pub use runtime::{AsmRuntimeParams, SpecV2Params};
pub use strata_asm_admin_types::{AdministrationInitConfig, ConfirmationDepths};
pub use strata_asm_bridge_types::BridgeInitConfig;
pub use strata_asm_checkpoint_types::CheckpointInitConfig;
pub use verification::InvalidAsmGenesisParams;
