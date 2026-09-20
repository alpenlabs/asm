//! ASM STF [`ZkVmProgram`] definition.

use moho_runtime_impl::RuntimeInput;
use moho_types::StepMohoAttestation;
use ssz::{decode::Decode, encode::Encode};
use strata_asm_common::AsmSpec;
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
/// into the ZKVM guest and how the resulting [`StepMohoAttestation`] is extracted from
/// the proof's public values.
#[derive(Debug)]
pub struct AsmStfProofProgram;

impl ZkVmProgram for AsmStfProofProgram {
    type Input = RuntimeInput;
    type Output = StepMohoAttestation;

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
        StepMohoAttestation::from_ssz_bytes(public_values.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Other(e.to_string()),
            }
        })
    }
}

impl AsmStfProofProgram {
    /// Builds a native test host with a concrete spec captured outside the witness.
    pub fn native_host<S: AsmSpec + Send + Sync + 'static>(spec: S) -> NativeHost {
        NativeHost::new_with_random_key(move |zkvm| process_asm_stf(zkvm, &spec))
    }

    /// Executes the program using the native host.
    pub fn execute(
        input: &<Self as ZkVmProgram>::Input,
    ) -> ZkVmResult<<Self as ZkVmProgram>::Output> {
        // Get the native host and delegate to the trait's execute method
        let host = Self::native_host(StrataAsmSpec);
        let summary = <Self as ZkVmProgram>::execute(input, &host)?;
        <Self as ZkVmProgram>::process_output::<NativeHost>(summary.public_values())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use moho_runtime_impl::RuntimeInput;
    use ssz::Encode;
    use strata_asm_common::{AnchorState, AsmSpec, SpecId, Stage};
    use strata_asm_spec::StrataAsmSpec;
    use strata_predicate::PredicateKey;
    use zkaleido::ZkVmProgram;

    use crate::{
        program::AsmStfProofProgram,
        test_utils::{create_asm_step_input, create_genesis_anchor_state, create_moho_state},
    };

    struct ObservedSpec(Arc<AtomicUsize>);

    impl AsmSpec for ObservedSpec {
        const ID: SpecId = StrataAsmSpec::ID;
        type GenesisParams = <StrataAsmSpec as AsmSpec>::GenesisParams;

        fn prepare(&self, state: &AnchorState) -> AnchorState {
            self.0.fetch_add(1, Ordering::SeqCst);
            StrataAsmSpec.prepare(state)
        }

        fn call_subprotocols(&self, stage: &mut impl Stage) {
            StrataAsmSpec.call_subprotocols(stage);
        }

        fn construct_genesis_state(&self, params: &Self::GenesisParams) -> AnchorState {
            StrataAsmSpec.construct_genesis_state(params)
        }

        fn genesis_l1_height(&self, params: &Self::GenesisParams) -> u64 {
            StrataAsmSpec.genesis_l1_height(params)
        }
    }

    /// Creates a runtime input for a single ASM STF step.
    fn create_runtime_input() -> RuntimeInput {
        let step_input = create_asm_step_input();
        let inner_pre_state = create_genesis_anchor_state(step_input.block());
        let moho_pre_state = create_moho_state(&inner_pre_state, PredicateKey::always_accept());
        RuntimeInput::new(
            moho_pre_state,
            inner_pre_state.as_ssz_bytes(),
            step_input.as_ssz_bytes(),
        )
    }

    #[test]
    fn test_stf() {
        let runtime_input = create_runtime_input();

        let output = AsmStfProofProgram::execute(&runtime_input).unwrap();
        // A wrapper with the same rules verifies that native execution uses
        // the supplied spec, rather than silently falling back to StrataAsmSpec.
        let preparations = Arc::new(AtomicUsize::new(0));
        let host = AsmStfProofProgram::native_host(ObservedSpec(preparations.clone()));
        let summary = <AsmStfProofProgram as ZkVmProgram>::execute(&runtime_input, &host).unwrap();
        assert_eq!(summary.public_values().as_bytes(), output.as_ssz_bytes());
        assert_eq!(preparations.load(Ordering::SeqCst), 1);
    }
}
