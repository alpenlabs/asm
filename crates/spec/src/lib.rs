//! # Strata ASM Specification
//!
//! This crate provides the Anchor State Machine (ASM) specification for the Strata protocol.
//!
//! - [`StrataAsmSpec`] — declares which subprotocols are active and their invocation order.
//! - [`construct_genesis_state`] — builds the genesis
//!   [`AnchorState`](strata_asm_common::AnchorState) from
//!   [`GenesisParams`](strata_asm_params::GenesisParams).

mod genesis;
mod spec;

pub use genesis::construct_genesis_state;
pub use spec::StrataAsmSpec;
