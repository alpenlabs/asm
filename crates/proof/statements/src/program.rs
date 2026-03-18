//! ASM STF [`ZkVmProgram`] definition.

use moho_runtime_impl::RuntimeInput;
use moho_types::MohoAttestation;
use ssz::{decode::Decode, encode::Encode};
use strata_asm_spec::StrataAsmSpec;
use zkaleido::{
    DataFormatError, ProofType, PublicValues, ZkVmError, ZkVmHost, ZkVmInputBuilder,
    ZkVmInputResult, ZkVmProgram, ZkVmResult,
};
use zkaleido_native_adapter::NativeHost;

use crate::statements::process_asm_stf;

/// The ASM STF program for ZKVM proof generation and verification.
///
/// This implements [`ZkVmProgram`] to define how the ASM STF runtime input is serialized
/// into the ZKVM guest and how the resulting [`MohoAttestation`] is extracted from the
/// proof's public values.
#[derive(Debug)]
pub struct AsmStfProofProgram;

impl ZkVmProgram for AsmStfProofProgram {
    type Input = RuntimeInput;
    type Output = MohoAttestation;

    fn name() -> String {
        "ASM STF".to_string()
    }

    fn proof_type() -> ProofType {
        ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: ZkVmInputBuilder<'a>,
    {
        let mut input_builder = B::new();
        input_builder.write_buf(&input.as_ssz_bytes())?;
        input_builder.build()
    }

    fn process_output<H>(public_values: &PublicValues) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: ZkVmHost,
    {
        MohoAttestation::from_ssz_bytes(public_values.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Other(e.to_string()),
            }
        })
    }
}

impl AsmStfProofProgram {
    /// Native host that can be used for testing
    pub fn native_host(spec: StrataAsmSpec) -> NativeHost {
        NativeHost::new(move |zkvm| {
            process_asm_stf(zkvm, &spec);
        })
    }

    /// Executes the program using the native host.
    pub fn execute(
        input: &<Self as ZkVmProgram>::Input,
        spec: StrataAsmSpec,
    ) -> ZkVmResult<<Self as ZkVmProgram>::Output> {
        // Get the native host and delegate to the trait's execute method
        let host = Self::native_host(spec);
        <Self as ZkVmProgram>::execute(input, &host)
    }
}

#[cfg(test)]
mod tests {

    use crate::{program::AsmStfProofProgram, test_utils::create_runtime_input_and_spec};

    #[test]
    fn test_stf() {
        let (runtime_input, spec) = create_runtime_input_and_spec();

        let output = AsmStfProofProgram::execute(&runtime_input, spec).unwrap();
        dbg!(output);
    }
}
