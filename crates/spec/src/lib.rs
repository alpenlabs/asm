//! # Strata ASM Specification
//!
//! This crate provides the Anchor State Machine (ASM) specification for the Strata protocol.
//! The ASM specification defines which subprotocols are enabled, their genesis configurations,
//! and protocol-level parameters like magic bytes.

use strata_asm_common::{AsmSpec, Stage};
use strata_asm_params::AsmParams;
use strata_asm_proto_administration::AdministrationSubprotocol;
use strata_asm_proto_bridge_v1::BridgeV1Subproto;
use strata_asm_proto_checkpoint::subprotocol::CheckpointSubprotocol;

mod genesis;

/// ASM specification for the Strata protocol.
///
/// Implements the [`AsmSpec`] trait to define subprotocol processing order,
/// magic bytes for L1 transaction filtering, and genesis configurations.
#[derive(Debug)]
pub struct StrataAsmSpec;

impl StrataAsmSpec {
    /// Compatibility shim — `StrataAsmSpec` is now a unit struct and does not
    /// use params. This constructor exists only for downstream callers that
    /// have not yet been updated.
    pub fn from_asm_params(_params: &AsmParams) -> Self {
        Self
    }
}

impl AsmSpec for StrataAsmSpec {
    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeV1Subproto>();
    }
}
