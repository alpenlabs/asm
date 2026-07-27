use serde::{Deserialize, Serialize};

mod bridge;
mod checkpoint;

pub use bridge::BridgeInitConfig;
pub use checkpoint::CheckpointInitConfig;
pub use strata_asm_admin_types::{
    AdminTxType, AdministrationInitConfig, ConfirmationDepths, Role, UpdateTxType,
};

/// A configured subprotocol that can be registered in [`AsmParams`](crate::AsmParams).
///
/// Each variant carries the configuration for a single ASM subprotocol.
/// The list of instances stored in `AsmParams` determines which subprotocols
/// are active for a given network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubprotocolInstance {
    /// Administration subprotocol for system upgrades.
    Admin(AdministrationInitConfig),

    /// Bridge V1 subprotocol for deposit/withdrawal management.
    Bridge(BridgeInitConfig),

    /// Checkpoint subprotocol for OL checkpoint verification.
    Checkpoint(CheckpointInitConfig),
}
