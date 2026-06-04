use std::str::FromStr;

mod asm_stf;
mod moho;

use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_predicate::{PredicateKey, PredicateTypeId::Sp1Groth16};
use zkaleido::{ExecutionSummary, ProofReceiptWithMetadata};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

/// On-disk 32-byte artifact carrying the moho pre-state's inner-state commitment (the ASM state
/// root) that the hardcoded ASM STF proof transitions from. Regenerated alongside the proof by
/// `--generate-proof` so the two files stay in sync; consumed by moho eval to rebuild a matching
/// `MohoState` without ever touching ASM types at runtime.
pub(crate) const INITIAL_ASM_STATE_ROOT_FILE: &str = "asm-stf_initial_asm_state_root.bin";

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

/// Runs SP1 programs to generate proofs and persists each program's artifacts before the next
/// program runs. The per-program save-on-completion ordering is load-bearing: `moho::gen_proof`
/// reads `asm-stf_SP1_v6.1.0.proof.bin` and `asm-stf_initial_asm_state_root.bin` from disk, so
/// when both programs are requested together the asm-stf artifacts must already be on disk by
/// the time moho runs — otherwise moho would prove against a stale asm-stf proof / root pair.
pub(crate) async fn gen_and_save_sp1_proofs(programs: &[GuestProgram]) {
    for program in programs {
        match program {
            GuestProgram::AsmStf => {
                let (proof, initial_asm_state_root) = asm_stf::gen_proof_and_initial_root().await;
                save_proof(&proof, program.as_str());
                asm_stf::save_initial_asm_state_root(&initial_asm_state_root);
            }
            GuestProgram::Moho => {
                let proof = moho::gen_proof().await;
                save_proof(&proof, program.as_str());
            }
        }
    }
}

fn save_proof(proof: &ProofReceiptWithMetadata, program_name: &str) {
    proof
        .save(program_name)
        .unwrap_or_else(|e| panic!("failed to save proof for {program_name}: {e}"));
}

pub(crate) fn compute_sp1_predicate_key(program_vk_hash: [u8; 32]) -> PredicateKey {
    let sp1_verifier: SP1Groth16Verifier =
        SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_vk_hash, *VK_ROOT_BYTES, true).unwrap();
    let condition_bytes = sp1_verifier.to_uncompressed_bytes();
    PredicateKey::new(Sp1Groth16, condition_bytes)
}
