//! Core type definitions for the Strata ASM bridge system.
//!
//! This crate provides the foundational types used across ASM bridge components for operator
//! management and withdrawal processing.
//!
//! # Operator Management
//!
//! Types for working with bridge operators in multisig sets:
//!
//! - [`OperatorIdx`] — unique identifier for an operator.
//! - [`OperatorSelection`] — specifies whether a withdrawal should be assigned to a specific
//!   operator or any eligible one.
//! - [`OperatorBitmap`] — memory-efficient bitmap for tracking active operators.
//! - [`filter_eligible_operators`] — determines which operators are eligible for assignment based
//!   on notary membership, previous assignment history, and current active status.
//!
//! # Withdrawal Processing
//!
//! - [`WithdrawalIntent`] — a user's request to withdraw an amount to a destination, optionally via
//!   a preferred operator.
//! - [`WithdrawalOutput`] — the destination and amount an assignment must pay out.
//!
//! # Bridge Gateway
//!
//! The crate also defines the [`BRIDGE_GATEWAY_ACCT_ID`] and [`BRIDGE_GATEWAY_ACCT_SERIAL`]
//! constants that identify the bridge's special gateway account.

use strata_identifiers::{AccountId, AccountSerial};

mod operator;
mod safe_harbour;
mod withdrawal;

pub use operator::{
    OperatorBitmap, OperatorBitmapError, OperatorIdx, OperatorSelection, filter_eligible_operators,
};
pub use safe_harbour::{SafeHarbour, SafeHarbourAddress};
pub use withdrawal::{WithdrawalIntent, WithdrawalOutput};

const BRIDGE_GATEWAY_REF: u8 = 0x10;

/// Account ID that we use for the bridge gateway account.
pub const BRIDGE_GATEWAY_ACCT_ID: AccountId = AccountId::special(BRIDGE_GATEWAY_REF);

/// Serial of the bridge gateway account.
pub const BRIDGE_GATEWAY_ACCT_SERIAL: AccountSerial = AccountSerial::reserved(BRIDGE_GATEWAY_REF);
