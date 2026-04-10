//! # Debug ASM Specification
//!
//! This crate provides the Debug ASM specification for the Strata protocol.
//! The Debug ASM spec wraps the regular ASM spec and adds debug capabilities for testing.
//!
//! **Security Note**: This spec should only be used in testing environments.

use strata_asm_common::{AnchorState, AsmSpec, SectionState, Stage, Subprotocol};
use strata_asm_params::AsmParams;
use strata_asm_proto_debug_v1::DebugSubproto;
use strata_asm_spec::{StrataAsmSpec, construct_genesis_state};

/// Debug ASM specification that includes the debug subprotocol.
///
/// This specification wraps the regular ASM spec and adds debug capabilities for testing.
/// It delegates most functionality to the wrapped production spec but adds the debug subprotocol
/// to the processing pipeline.
///
/// **Security Note**: This spec should only be used in testing environments.
#[derive(Debug)]
pub struct DebugAsmSpec {
    /// The wrapped production ASM spec
    inner: StrataAsmSpec,
}

impl AsmSpec for DebugAsmSpec {
    type Params = AsmParams;

    fn call_subprotocols(&self, stage: &mut impl Stage) {
        // Call debug subprotocol first
        stage.invoke_subprotocol::<DebugSubproto>();

        // Then call all production subprotocols
        self.inner.call_subprotocols(stage);
    }

    fn construct_genesis_state(&self, params: &Self::Params) -> AnchorState {
        construct_debug_genesis_state(params)
    }
}

impl DebugAsmSpec {
    /// Creates a debug ASM spec by wrapping a production spec.
    ///
    /// This adds debug capabilities to an existing production spec.
    pub fn new(inner: StrataAsmSpec) -> Self {
        Self { inner }
    }
}

/// Builds the genesis [`AnchorState`] for the debug spec.
///
/// This wraps [`construct_genesis_state`] and prepends the debug subprotocol
/// section, mirroring the invocation order in [`DebugAsmSpec::call_subprotocols`].
pub fn construct_debug_genesis_state(params: &AsmParams) -> AnchorState {
    let mut state = construct_genesis_state(params);

    let debug_state = DebugSubproto::init(&());
    let debug_section = SectionState::from_state::<DebugSubproto>(&debug_state);

    // Prepend so section order matches call_subprotocols order
    // (debug first, then production subprotocols).
    let mut sections: Vec<_> = state.sections.to_vec();
    sections.insert(0, debug_section);
    state.sections = sections.into();

    state
}
