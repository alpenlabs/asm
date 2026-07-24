//! Bridge V1 Subprotocol State
//!
//! This crate holds the persistent state for the Strata bridge subprotocol,
//! separate from the state transition logic in `strata-asm-proto-bridge-v1`.
//!
//! The state consists of several key components:
//!
//! - **Operators**: Entities that process withdrawals and maintain bridge security
//! - **Deposits**: Bitcoin UTXOs locked to N/N multisig operator addresses
//! - **Assignments**: Task assignments linking deposits to specific operators
//! - **Withdrawals**: Commands for operators to release funds from the multisig.
//!
//! The main entry point is [`BridgeV1State`], the state container the
//! subprotocol crate operates on.

pub mod assignment;
pub mod bridge;
pub mod deposit;
mod errors;
pub mod operator;
pub mod withdrawal;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use assignment::AssignmentEntry;
pub use bridge::BridgeV1State;
pub use deposit::DepositEntry;
pub use errors::*;
pub use operator::NnScriptIdx;
pub use withdrawal::OperatorClaimUnlock;
