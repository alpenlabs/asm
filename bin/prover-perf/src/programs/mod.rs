use std::str::FromStr;

mod asm_stf;
mod moho;

use sp1_verifier::GROTH16_VK_BYTES;
use strata_predicate::{PredicateKey, PredicateTypeId::Sp1Groth16};
use zkaleido::PerformanceReport;
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum GuestProgram {
    AsmStf,
    Moho,
}

impl FromStr for GuestProgram {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "asm-stf" => Ok(GuestProgram::AsmStf),
            "moho" => Ok(GuestProgram::Moho),
            _ => Err(format!("unknown program: {s}")),
        }
    }
}

/// Runs SP1 programs to generate reports.
pub(crate) fn run_sp1_programs(programs: &[GuestProgram]) -> Vec<PerformanceReport> {
    programs
        .iter()
        .map(|program| match program {
            GuestProgram::AsmStf => asm_stf::gen_perf_report(),
            GuestProgram::Moho => moho::gen_perf_report(),
        })
        .collect()
}

pub(crate) fn sp1_predicate_key(program_vk_hash: [u8; 32]) -> PredicateKey {
    let sp1_verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_vk_hash).unwrap();
    let condition_bytes = sp1_verifier.vk.to_uncompressed_bytes();
    PredicateKey::new(Sp1Groth16, condition_bytes)
}
