use std::str::FromStr;

mod asm_stf;
mod moho;

use sp1_verifier::GROTH16_VK_BYTES;
use strata_predicate::{PredicateKey, PredicateTypeId::Sp1Groth16};
use zkaleido::{PerformanceReport, ProofReceiptWithMetadata};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum GuestProgram {
    AsmStf,
    Moho,
}

impl GuestProgram {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::AsmStf => "asm-stf",
            Self::Moho => "moho",
        }
    }
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
pub(crate) fn gen_sp1_perf_report(programs: &[GuestProgram]) -> Vec<PerformanceReport> {
    programs
        .iter()
        .map(|program| match program {
            GuestProgram::AsmStf => asm_stf::gen_perf_report(),
            GuestProgram::Moho => moho::gen_perf_report(),
        })
        .collect()
}

/// Runs SP1 programs to generate reports.
pub(crate) fn gen_sp1_proof(programs: &[GuestProgram]) -> Vec<(String, ProofReceiptWithMetadata)> {
    programs
        .iter()
        .map(|program| match program {
            GuestProgram::AsmStf => asm_stf::gen_proof(),
            GuestProgram::Moho => moho::gen_proof(),
        })
        .collect()
}

pub(crate) fn compute_sp1_predicate_key(program_vk_hash: [u8; 32]) -> PredicateKey {
    let sp1_verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_vk_hash).unwrap();
    let condition_bytes = sp1_verifier.vk.to_uncompressed_bytes();
    PredicateKey::new(Sp1Groth16, condition_bytes)
}
