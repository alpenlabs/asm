use std::str::FromStr;

mod asm_stf;
mod moho;

use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_predicate::{PredicateKey, PredicateTypeId::Sp1Groth16};
use zkaleido::{ExecutionSummary, ProofReceiptWithMetadata};
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

/// Runs SP1 programs to generate execution summaries.
pub(crate) async fn gen_sp1_execution_summaries(
    programs: &[GuestProgram],
) -> Vec<ExecutionSummary> {
    let mut summaries = Vec::with_capacity(programs.len());
    for program in programs {
        let summary = match program {
            GuestProgram::AsmStf => asm_stf::gen_execution_summary().await,
            GuestProgram::Moho => moho::gen_execution_summary().await,
        };
        summaries.push(summary);
    }
    summaries
}

/// Runs SP1 programs to generate proofs.
pub(crate) async fn gen_sp1_proof(programs: &[GuestProgram]) -> Vec<ProofReceiptWithMetadata> {
    let mut proofs = Vec::with_capacity(programs.len());
    for program in programs {
        let proof = match program {
            GuestProgram::AsmStf => asm_stf::gen_proof().await,
            GuestProgram::Moho => moho::gen_proof().await,
        };
        proofs.push(proof);
    }
    proofs
}

pub(crate) fn compute_sp1_predicate_key(program_vk_hash: [u8; 32]) -> PredicateKey {
    let sp1_verifier =
        SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_vk_hash, *VK_ROOT_BYTES, true).unwrap();
    let condition_bytes =
        borsh::to_vec(&sp1_verifier).expect("borsh serialization of sp1 verifier is infalliable");
    PredicateKey::new(Sp1Groth16, condition_bytes)
}
