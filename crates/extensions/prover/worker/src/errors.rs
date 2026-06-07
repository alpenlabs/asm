//! Error types for the prover worker setup surface.
//!
//! The orchestration loop itself stays `anyhow`-based (it logs and continues on
//! transient failures); these typed errors cover the builder/launch path.

use thiserror::Error;

/// Result alias for prover-worker setup operations.
pub type ProverResult<T> = Result<T, ProverError>;

/// Errors surfaced while building or launching the prover worker.
#[derive(Debug, Error)]
pub enum ProverError {
    /// A required dependency was not supplied to the builder.
    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),

    /// Any other error, typically from backend construction.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
