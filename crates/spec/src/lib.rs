//! # Strata ASM Specification
//!
//! This crate provides the Anchor State Machine (ASM) specification for the Strata protocol.
//!
//! - [`StrataAsmSpec`] — declares which subprotocols are active and their invocation order.
//! - [`StrataAsmSpecV1`] — its successor, which commits `OperatorClaimUnlockV1` export leaves.
//! - [`StrataAsmSpecV2`] — the successor to both, which replaces the admin confirmation depths with
//!   the ones in the `spec_v2` section of the runtime params.
//! - [`construct_genesis_state`] — builds the genesis
//!   [`AnchorState`](strata_asm_common::AnchorState) from
//!   [`AsmGenesisParams`](strata_asm_params::AsmGenesisParams).
//!
//! Enable the optional `host` feature for the shared native-spec catalog and worker registry
//! assembly in `host`. Guest builds use the default feature set without worker dependencies.

mod genesis;
mod specs;

pub use genesis::construct_genesis_state;
pub use specs::{StrataAsmSpec, StrataAsmSpecV1, StrataAsmSpecV2};

#[cfg(feature = "host")]
pub mod host;
