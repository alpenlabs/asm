//! ASM STF proof statements.

use moho_runtime_impl::{compute_moho_attestation, RuntimeInput};
use ssz::{Decode, Encode};
use strata_asm_common::StfParams;
use strata_asm_spec::StrataAsmSpec;
use zkaleido::ZkVmEnv;

use crate::moho_program::program::AsmStfProgram;

/// Processes the ASM state transition function inside the ZKVM guest.
///
/// This is the main entrypoint for the ASM STF proof. It deserializes the runtime input
/// from the ZKVM, runs the Moho runtime verification against the provided spec, and
/// commits the resulting attestation as the proof's public output.
///
/// # Note
///
/// `stf_params` must be hardcoded by the outer guest program rather than read from the
/// ZKVM input: together with the spec it defines the trusted chain parameters that the
/// proof is verified against, so the verifying key must commit to it.
pub fn process_asm_stf(zkvm: &impl ZkVmEnv, stf_params: StfParams) {
    let runtime_input_bytes = zkvm.read_buf();
    let runtime_input = RuntimeInput::from_ssz_bytes(&runtime_input_bytes)
        .expect("failed to deserialize runtime input for SSZ bytes");

    let spec = StrataAsmSpec::new(stf_params);
    let attestation = compute_moho_attestation::<AsmStfProgram>(runtime_input, &spec);

    let attestation_bytes = attestation.as_ssz_bytes();
    zkvm.commit_buf(&attestation_bytes);
}
