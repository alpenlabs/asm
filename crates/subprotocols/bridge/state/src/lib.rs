//! Bridge V1 Subprotocol State
//!
//! This crate holds the persistent state for the Strata bridge subprotocol,
//! separate from the state transition logic in `strata-asm-proto-bridge`.
//!
//! The state consists of several key components:
//!
//! - **Operators**: Entities that process withdrawals and maintain bridge security
//! - **Deposits**: Bitcoin UTXOs locked to N/N multisig operator addresses
//! - **Assignments**: Task assignments linking deposits to specific operators
//! - **Withdrawals**: Commands for operators to release funds from the multisig.
//!
//! The main entry point is [`BridgeStateV1`], the state container the
//! subprotocol crate operates on.

pub mod assignment;
pub mod bridge;
pub mod deposit;
mod errors;
pub mod operator;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use assignment::AssignmentEntry;
pub use bridge::BridgeStateV1;
pub use deposit::DepositEntry;
pub use errors::*;
pub use operator::NnScriptIdx;
// Defined in `strata-asm-bridge-types`; re-exported so downstream users keep finding it here.
pub use strata_asm_bridge_types::OperatorClaimUnlock;
