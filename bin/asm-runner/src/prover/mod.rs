//! Proof orchestration for the ASM runner.
//!
//! Manages the lifecycle of ASM step proofs and Moho recursive proofs by
//! scheduling jobs on a remote prover service and reconciling results.

pub(crate) mod config;
mod input;
mod orchestrator;
mod proof_store;
mod queue;

pub(crate) use self::{input::InputBuilder, orchestrator::ProofOrchestrator};
