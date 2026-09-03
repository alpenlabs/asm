//! ASM STF proof statements.
//!
//! One statement per specification. Each is the entrypoint of exactly one guest
//! artifact, which is what makes an artifact's rules a property of the binary
//! rather than of its input: see [`AsmStfProgram`].

use moho_runtime_impl::{compute_moho_attestation, RuntimeInput};
use ssz::{Decode, Encode};
use strata_asm_common::AsmSpec;
use strata_asm_spec::{StrataAsmSpecV0, StrataAsmSpecV1};
use zkaleido::ZkVmEnv;

use crate::moho_program::program::AsmStfProgram;

/// Processes the ASM state transition function under the released (`v0`) rules.
///
/// The entrypoint of the `v0` guest artifact. It exists so the blocks that ran
/// under the released rules stay provable after an upgrade: the recursive chain
/// re-verifies every step from genesis, so history has to remain reproducible
/// under the rules that governed it.
pub fn process_asm_stf_v0(zkvm: &impl ZkVmEnv) {
    process_asm_stf_under(zkvm, &StrataAsmSpecV0);
}

/// Processes the ASM state transition function under the current (`v1`) rules.
///
/// The entrypoint of the current guest artifact.
pub fn process_asm_stf(zkvm: &impl ZkVmEnv) {
    process_asm_stf_under(zkvm, &StrataAsmSpecV1);
}

/// Processes the ASM state transition function inside the ZKVM guest.
///
/// Deserializes the runtime input from the ZKVM, runs the Moho runtime
/// verification against `spec`, and commits the resulting attestation as the
/// proof's public output.
///
/// # Note
///
/// `spec` is supplied by the caller — one of the entrypoints above — and never
/// read from the ZKVM input. It defines the trusted chain parameters the proof is
/// verified against, so a guest that took it as input would let its own prover
/// choose the rules it is judged by.
fn process_asm_stf_under<S: AsmSpec>(zkvm: &impl ZkVmEnv, spec: &S) {
    let runtime_input_bytes = zkvm.read_buf();
    let runtime_input = RuntimeInput::from_ssz_bytes(&runtime_input_bytes)
        .expect("failed to deserialize runtime input for SSZ bytes");

    let attestation = compute_moho_attestation::<AsmStfProgram<S>>(runtime_input, spec);

    let attestation_bytes = attestation.as_ssz_bytes();
    zkvm.commit_buf(&attestation_bytes);
}
