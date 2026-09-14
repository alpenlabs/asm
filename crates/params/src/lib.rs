//! Genesis configuration for the Anchor State Machine (ASM).
//!
//! Provides [`StrataGenesisConfig`], which bundles the L1 magic bytes, the
//! genesis L1 view, and the typed subprotocol configurations needed to
//! construct the initial ASM state. The per-subprotocol configurations are
//! defined in each subprotocol's own types
//! crate and only aggregated (and re-exported) here.
//!
//! After genesis, this configuration is not consulted for STF or subprotocol
//! dispatch. The runner retains it for the control RPC.

mod params;

pub use params::StrataGenesisConfig;
pub use strata_asm_admin_types::AdministrationInitConfig;
pub use strata_asm_bridge_types::BridgeInitConfig;
pub use strata_asm_checkpoint_types::CheckpointInitConfig;
