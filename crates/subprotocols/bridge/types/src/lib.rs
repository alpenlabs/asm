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
//! # Operator Claims
//!
//! An assigned operator's claim to unlock a deposit UTXO after a fulfilled withdrawal. Only the
//! claim's hash leaves the ASM, and that hash is consensus state, so the claim is versioned:
//!
//! - [`OperatorClaimUnlockV0`] — names the assignee by table index. Frozen; what the subprotocol
//!   emits today.
//! - [`OperatorClaimUnlockV1`] — names the assignee by public key. Defined, not yet emitted.
//!
//! # Configuration
//!
//! - [`BridgeInitConfig`] — genesis configuration for the bridge subprotocol.

mod claim;
mod config;
mod operator;
mod safe_harbor;
mod withdrawal;

pub use claim::{OperatorClaimUnlockV0, OperatorClaimUnlockV1};
pub use config::BridgeInitConfig;
pub use operator::{
    OperatorBitmap, OperatorBitmapError, OperatorIdx, OperatorSelection, filter_eligible_operators,
};
pub use safe_harbor::{SafeHarbor, SafeHarborAddress};
pub use withdrawal::{WithdrawalIntent, WithdrawalOutput};
