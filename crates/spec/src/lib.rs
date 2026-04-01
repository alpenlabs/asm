//! # Strata ASM Specification
//!
//! This crate provides the Anchor State Machine (ASM) specification for the Strata protocol.
//! The ASM specification defines which subprotocols are enabled, their genesis configurations,
//! and protocol-level parameters like magic bytes.

use strata_asm_common::{AsmSpec, Loader, Stage};
use strata_asm_params::AsmParams;
use strata_asm_proto_administration::AdministrationSubprotocol;
use strata_asm_proto_bridge_v1::BridgeV1Subproto;
use strata_asm_proto_checkpoint::subprotocol::CheckpointSubprotocol;
use strata_l1_txfmt::MagicBytes;

mod genesis;

/// ASM specification for the Strata protocol.
///
/// Implements the [`AsmSpec`] trait to define subprotocol processing order,
/// magic bytes for L1 transaction filtering, and genesis configurations.
#[derive(Debug)]
pub struct StrataAsmSpec(AsmParams);

impl AsmSpec for StrataAsmSpec {
    fn magic_bytes(&self) -> MagicBytes {
        self.0.magic
    }

    fn load_subprotocols(&self, loader: &mut impl Loader) {
        // unwrap is safe: validated at construction
        loader
            .load_subprotocol::<AdministrationSubprotocol>(self.0.admin_config().unwrap().clone());
        loader
            .load_subprotocol::<CheckpointSubprotocol>(self.0.checkpoint_config().unwrap().clone());
        loader.load_subprotocol::<BridgeV1Subproto>(self.0.bridge_config().unwrap().clone());
    }

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        stage.invoke_subprotocol::<AdministrationSubprotocol>();
        stage.invoke_subprotocol::<CheckpointSubprotocol>();
        stage.invoke_subprotocol::<BridgeV1Subproto>();
    }
}

impl StrataAsmSpec {
    /// Creates a new ASM spec, validating that all required subprotocols are present.
    #[cfg(not(target_os = "zkvm"))]
    pub fn new(params: AsmParams) -> Self {
        assert!(
            params.admin_config().is_some(),
            "AsmParams missing Admin subprotocol"
        );
        assert!(
            params.checkpoint_config().is_some(),
            "AsmParams missing Checkpoint subprotocol"
        );
        assert!(
            params.bridge_config().is_some(),
            "AsmParams missing Bridge subprotocol"
        );
        Self(params)
    }

    #[cfg(not(target_os = "zkvm"))]
    pub fn from_asm_params(params: &AsmParams) -> Self {
        Self::new(params.clone())
    }

    /// Creates an ASM spec from the `ASM_PARAMS_JSON` environment variable that was
    /// validated and embedded at compile time by the build script.
    #[cfg(target_os = "zkvm")]
    pub fn new() -> Self {
        const ASM_PARAMS_JSON: &str = env!("ASM_PARAMS_JSON");
        let params: AsmParams =
            serde_json::from_str(ASM_PARAMS_JSON).expect("ASM_PARAMS_JSON validated at build time");
        Self(params)
    }

    /// Returns a reference to the inner [`AsmParams`].
    pub fn params(&self) -> &AsmParams {
        &self.0
    }
}
