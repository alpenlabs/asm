//! # Strata ASM Specification
//!
//! This crate provides the Anchor State Machine (ASM) specification for the Strata protocol.
//!
//! - [`StrataAsmSpecV0`] — the rules as released in `v0.3.0-rc.2`.
//! - [`StrataAsmSpecV1`] — the current rules, plus the migration from v0.
//! - [`construct_v0_genesis_state`] / [`construct_v1_genesis_state`] — genesis
//!   [`AnchorState`](strata_asm_common::AnchorState) per specification.
//! - [`build_v0_bootstrap`] / [`build_v1_bootstrap`] — the same, validated into an
//!   [`AsmBootstrap`](strata_asm_common::AsmBootstrap) for the worker.

mod genesis;
mod spec;
mod targets;

pub use genesis::{
    build_v0_bootstrap, build_v1_bootstrap, construct_v0_genesis_state, construct_v1_genesis_state,
};
pub use spec::{StrataAsmSpecV0, StrataAsmSpecV1};
pub use targets::{StrataAsmTarget, StrataAsmTargets, TargetTableError};
