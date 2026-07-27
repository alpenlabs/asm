use serde::{Deserialize, Serialize};
pub use strata_asm_admin_types::{
    AdminTxType, AdministrationInitConfig, ConfirmationDepths, Role, UpdateTxType,
};
pub use strata_asm_proto_bridge_types::BridgeInitConfig;
pub use strata_asm_proto_checkpoint_types::CheckpointInitConfig;

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
