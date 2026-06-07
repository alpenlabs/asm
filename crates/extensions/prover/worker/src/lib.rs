//! # strata-asm-prover-worker
//!
//! Orchestrates remote ASM step proofs and Moho recursive proofs.
//!
//! The worker defines a [`ProverContext`] umbrella trait abstracting its
//! storage and chain-data dependencies, and a [`ProofOrchestrator`] that drives
//! proof scheduling and reconciliation generically over it — mirroring how the
//! ASM worker (`strata-asm-worker`) is built. Concrete sled-backed storage
//! lives in the sibling `strata-asm-prover-storage` crate; the binary supplies
//! the `ProverContext` impl that wires storage and the Bitcoin client together.

mod backend;
mod builder;
mod config;
mod errors;
mod handle;
mod input;
mod orchestrator;
mod proof_store;
mod queue;
mod traits;

pub use backend::{ProofBackend, ProofHost};
pub use builder::ProverWorkerBuilder;
pub use config::{BackendConfig, OrchestratorConfig};
pub use errors::{ProverError, ProverResult};
pub use handle::ProverWorkerHandle;
pub use input::{InputBuilder, MohoPrerequisite};
pub use orchestrator::ProofOrchestrator;
pub use traits::{AnchorStateReader, AuxDataReader, L1BlockProvider, ProverContext};
// In `sp1` builds the native host path is compiled out, leaving the
// `zkaleido-native-adapter` dependency otherwise unused; this keeps the
// `unused_crate_dependencies` lint satisfied.
#[cfg(feature = "sp1")]
use zkaleido_native_adapter as _;
