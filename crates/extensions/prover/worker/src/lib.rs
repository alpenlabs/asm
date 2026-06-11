//! # strata-asm-prover-worker
//!
//! Orchestrates remote ASM step proofs and Moho recursive proofs.
//!
//! Built on the `strata-service` framework, mirroring the ASM worker
//! (`strata-asm-worker`): a logic-only [`ProverService`] implements the
//! framework traits while all mutable data lives in [`ProverServiceState`], and
//! a [`ProverWorkerBuilder`] launches the service and returns a
//! [`ProverWorkerHandle`]. The worker defines a [`ProverContext`] umbrella trait
//! abstracting its storage and chain-data dependencies. The service is fed by
//! the Moho worker's commit subscription (overlaid with a periodic tick): each
//! committed block — already carrying a persisted MohoState — expands into the
//! ASM step proof and Moho recursive proof it requires. Concrete sled-backed
//! storage lives in the sibling
//! `strata-asm-prover-storage` crate; the binary supplies the `ProverContext`
//! impl that wires storage and the Bitcoin client together.

mod backend;
mod builder;
mod config;
mod constants;
mod errors;
mod handle;
mod input;
mod message;
mod proof_store;
mod queue;
mod service;
mod state;
mod traits;

pub use backend::{ProofBackend, ProofHost};
pub use builder::ProverWorkerBuilder;
pub use config::{BackendConfig, OrchestratorConfig};
pub use errors::{ProverError, ProverResult};
pub use handle::ProverWorkerHandle;
pub use input::{InputBuilder, MohoPrerequisite};
pub use message::ProverMessage;
pub use service::{ProverService, ProverStatus};
pub use state::ProverServiceState;
pub use traits::{AnchorStateReader, AuxDataReader, L1BlockProvider, ProverContext};
// In `sp1` builds the native host path is compiled out, leaving the
// `zkaleido-native-adapter` dependency otherwise unused; this keeps the
// `unused_crate_dependencies` lint satisfied.
#[cfg(feature = "sp1")]
use zkaleido_native_adapter as _;
