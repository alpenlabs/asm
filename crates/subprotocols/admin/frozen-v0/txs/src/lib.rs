//! Strata Administration Transaction Definitions and Parsing Logic
//!
//! FROZEN. A copy of `crates/subprotocols/admin/txs` as released in
//! `v0.3.0-rc.2` (`45a1fa2f52289b483dd9767b4ec9c80545d5789b`), kept so the
//! admin transactions already on L1 can still be parsed. Nothing here may be
//! "fixed": a change to these rules changes what historical blocks mean.
//!
//! # What the current crate does differently
//!
//! [`parser::SignedPayload`] derives SSZ `Encode`/`Decode` here, so the action
//! goes on the wire as a union and the SPS-50 tag's tx type is not consulted.
//! The current crate deliberately dropped those derives and selects the
//! concrete action from the tag instead, which is a wire-format break: bytes
//! written under these rules do not decode there, and vice versa. The derives
//! below are the reason this crate exists, not an oversight.
//!
//! # Adaptations from the release
//!
//! Imports only. The types crate was renamed (`strata_asm_params` ->
//! `strata_asm_admin_types`), and the bridge types now come from the shared
//! `strata_asm_bridge_types` rather than a frozen copy, its persisted layouts
//! being identical across the boundary. No logic differs.
//!
//! This module provides transaction types, parsing utilities, and constants for the Strata
//! Administration Subprotocol. It handles multisig-backed governance transactions that propose
//! and manage time-delayed configuration changes to the protocol.
//!
//! ## Transaction Types
//!
//! See [`strata_asm_admin_types::AdminTxType`] for the full list of supported transaction types.
//!
//! ## Core Structures
//!
//! - [`actions::MultisigAction`]: High-level multisig operations that can be proposed (Cancel or
//!   Update)
//! - [`actions::CancelAction`]: Specific action to cancel a pending update; embeds the target ID
//!   and the full `UpdateAction` payload so signers see what they're cancelling and role resolution
//!   does not require queue context
//! - [`actions::UpdateAction`]: Various update types (multisig, operator, sequencer, verifying key)

pub mod actions;
pub mod constants;
pub mod errors;
pub mod parser;
pub mod signing_message;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
