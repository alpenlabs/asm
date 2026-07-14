//! Error types for the prover worker.
//!
//! The crate is typed end to end: every crate-owned helper returns
//! [`ProverResult`]. `anyhow` survives only at the `strata-service` boundary
//! (its `Service`/`ServiceInput` signatures are external and fixed), where the
//! service adapter converts a [`ProverError`] into `anyhow::Error` via `?`.
//!
//! Every variant that wraps an underlying failure keeps it as an
//! [`Error::source`](std::error::Error::source), so the full cause chain is
//! preserved rather than flattened into a string. Concrete, always-available
//! error types (SSZ decode, the ZkVM remote client) are carried by their real
//! type; the heterogeneous storage/chain-source backends — whose error type
//! varies per implementor — are carried as a boxed `dyn Error`, which still
//! chains through `source()`.

use std::error::Error as StdError;

use thiserror::Error;

/// Boxed backend error. Used where the underlying error type varies per
/// implementor (the storage and chain-source traits) or is only present under a
/// build feature, so it cannot be named as a concrete variant field. It is still
/// carried as a `#[source]`, preserving the full cause chain.
pub(crate) type BoxedError = Box<dyn StdError + Send + Sync + 'static>;

/// Result alias for prover-worker operations.
pub type ProverResult<T> = Result<T, ProverError>;

/// Errors surfaced while building, launching, or running the prover worker.
#[derive(Debug, Error)]
pub enum ProverError {
    /// A required dependency was not supplied to the builder.
    #[error("missing required dependency: {0}")]
    MissingDependency(&'static str),

    /// A storage or chain-source read/write failed. The underlying backend
    /// error type varies per `ProverContext` implementor, so it is carried as a
    /// boxed source; `context` names the operation.
    #[error("{context}: {source}")]
    Storage {
        /// What the worker was doing when the backend failed.
        context: &'static str,
        /// The underlying backend error, preserved as the cause.
        #[source]
        source: BoxedError,
    },

    /// A value expected to be present in storage was missing.
    #[error("{0}")]
    NotFound(&'static str),

    /// Decoding an SSZ-encoded value out of a stored proof failed.
    #[error("failed to decode {what} from stored proof: {source}")]
    Decode {
        /// The value that failed to decode (e.g. an ASM attestation).
        what: &'static str,
        /// The underlying SSZ decode error, preserved as the cause.
        #[source]
        source: ssz::DecodeError,
    },

    /// Querying a remote proof's status failed.
    #[error("failed to query remote proof status: {0}")]
    RemoteStatus(#[source] zkaleido::ZkVmError),

    /// Retrieving a completed proof from the remote prover failed.
    #[error("failed to retrieve completed proof: {0}")]
    RemoteRetrieve(#[source] zkaleido::ZkVmError),

    /// Submitting a proof to the remote prover failed.
    #[error("failed to submit proof to remote prover: {0}")]
    RemoteSubmit(#[source] zkaleido::ZkVmError),

    /// A persisted remote proof ID could not be decoded into the host's typed
    /// proof ID.
    ///
    /// The host's `TryFrom` error is an unconstrained associated type (no
    /// `std::error::Error` bound), so there is no source to carry.
    #[error("failed to decode remote proof ID")]
    RemoteIdDecode,

    /// Constructing the ZK proof backend or resolving a predicate key failed.
    /// The underlying error is feature-gated (SP1/native), so it is carried as a
    /// boxed source rather than a concrete field.
    #[error("{context}: {source}")]
    Backend {
        /// What the worker was doing when backend construction failed.
        context: &'static str,
        /// The underlying error, preserved as the cause.
        #[source]
        source: BoxedError,
    },

    /// A requested backend does not match the binary's build features (e.g.
    /// `Sp1` requested without the `sp1` feature), or a backend that is not yet
    /// wired up was requested. There is no underlying error.
    #[error("{0}")]
    BackendUnavailable(&'static str),

    /// Launching the service on the `strata-service` framework failed. The
    /// framework's builder returns `anyhow::Error`, carried here as the cause.
    #[error("failed to launch prover service: {0}")]
    Launch(#[source] anyhow::Error),
}

impl ProverError {
    /// Builds a [`ProverError::Storage`] from a static context and a backend
    /// error, preserving the error as the cause chain.
    pub fn storage<E>(context: &'static str, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Storage {
            context,
            source: Box::new(source),
        }
    }

    /// Builds a [`ProverError::Backend`] from a static context and a backend
    /// error, preserving the error as the cause chain.
    pub fn backend<E>(context: &'static str, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Backend {
            context,
            source: Box::new(source),
        }
    }
}
