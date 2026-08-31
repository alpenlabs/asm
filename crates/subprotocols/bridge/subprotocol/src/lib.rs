//! Bridge V1 Subprotocol
//!
//! This crate implements the Strata bridge subprotocol.
//!
//! The bridge manages Bitcoin deposits, operators, withdrawal assignments,
//! between Bitcoin L1 and the orchestration layer.
//!
//! # Architecture
//!
//! The bridge consists of several key components:
//!
//! - **Operators**: Entities that process withdrawals and maintain bridge security
//! - **Deposits**: Bitcoin UTXOs locked to N/N multisig operator addresses
//! - **Assignments**: Task assignments linking deposits to specific operators
//! - **Withdrawals**: Commands for operators to release funds from the multisig.
//!
//! # Usage
//!
//! The main entry point is [`subprotocol::BridgeSubproto`], which implements the `Subprotocol`
//! trait for integration with the Anchor State Machine. It is parameterized by the operator
//! claim version it commits, and each released version is a type alias for one choice:
//! [`BridgeSubprotoV1`] commits [`OperatorClaimUnlockV0`] leaves, and [`BridgeSubprotoV2`]
//! commits [`OperatorClaimUnlockV1`] leaves. Both store bridge state in section schema 0.
//!
//! [`BridgeSubprotoV3`] also commits [`OperatorClaimUnlockV1`] leaves, but stores section
//! schema 1 ([`BridgeStateV2`]) so that it can mark an expired assignment unassignable instead
//! of halting when no active operator from the deposit's notary set can take it. Spec 2 invokes
//! it and migrates a schema-0 section with [`migrate_bridge_section`].

mod claim;
mod errors;
mod handler;
mod migration;
mod subprotocol;
mod validation;

#[cfg(test)]
mod test_utils;

pub use claim::{ClaimV0, ClaimV1, ClaimVersion};
pub use errors::*;
pub use migration::{decode_bridge_section, migrate_bridge_section};
pub use strata_asm_proto_bridge_msgs::BridgeIncomingMsg;
// Re-exported so downstream users keep finding the state types here.
pub use strata_asm_proto_bridge_state::{
    AssignmentEntry, AssignmentStatus, BridgeStateV1, BridgeStateV2, DepositEntry, NnScriptIdx,
    OperatorClaimUnlockV0, OperatorClaimUnlockV1, ReassignmentOutcome, ReassignmentReport,
};
pub use subprotocol::{BridgeSubproto, BridgeSubprotoV1, BridgeSubprotoV2, BridgeSubprotoV3};
