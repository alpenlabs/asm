//! # Strata ASM Specification
//!
//! This crate provides the Anchor State Machine (ASM) specification for the Strata protocol.
//!
//! - [`StrataAsmSpec`] — declares which subprotocols are active and their invocation order.
//! - [`construct_genesis_state`] — builds the genesis
//!   [`AnchorState`](strata_asm_common::AnchorState) from
//!   [`AsmParams`](strata_asm_params::AsmParams).
//!
//! Enable the optional `host` feature for the shared native-spec catalog and worker registry
//! assembly in `host`. Guest builds use the default feature set without worker dependencies.

mod genesis;
mod spec;

pub use genesis::construct_genesis_state;
pub use spec::StrataAsmSpec;

#[cfg(feature = "host")]
pub mod host;
