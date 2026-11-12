#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use ssz::Decode;
use strata_asm_params::SpecV2Params;
use strata_asm_proof_impl::statements::process_asm_stf;
use strata_asm_spec::StrataAsmSpecV2;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

/// The `spec_v2` section of the runtime params as an SSZ `Option`, `None` if the file has none.
/// `build.rs` writes it from the params file at `ASM_PARAMS_PATH`.
const SPEC_V2_PARAMS_SSZ: &[u8] = include_bytes!("../../generated/asm-spec-v2-params.ssz");

fn main() {
    let section = Option::<SpecV2Params>::from_ssz_bytes(SPEC_V2_PARAMS_SSZ)
        .expect("embedded spec 2 params must decode");
    let spec = StrataAsmSpecV2::new(section.map(|section| section.confirmation_depths));
    process_asm_stf(&Sp1ZkVmEnv, &spec)
}
