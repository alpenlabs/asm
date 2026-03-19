//! Proof orchestration for the ASM runner.
//!
//! Manages the lifecycle of ASM step proofs and Moho recursive proofs by
//! scheduling jobs on a remote prover service and reconciling results.

// Re-export the proof DB crate so the unused-crate-dependencies lint is satisfied.
// The orchestrator will use `SledProofDb` directly once the full orchestrator struct is wired up.
pub(crate) use strata_asm_proof_db as proof_db;

pub(crate) mod config;
pub(crate) mod queue;
