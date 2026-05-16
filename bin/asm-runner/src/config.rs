//! Configuration structures for ASM RPC server

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{prover::config::OrchestratorConfig, retry::RetryConfig};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AsmRpcConfig {
    /// RPC server configuration
    pub rpc: RpcConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Bitcoin node configuration
    pub bitcoin: BitcoinConfig,
    /// Proof orchestrator configuration (optional — omit to disable proof generation).
    pub orchestrator: Option<OrchestratorConfig>,
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RpcConfig {
    /// Host address to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseConfig {
    /// SledDB path (directory)
    pub path: PathBuf,
    /// Optional number of threads for database operations.
    pub num_threads: Option<usize>,
    /// Optional number of retries for failed database operations.
    pub retry_count: Option<u16>,
    /// Optional number between retries for failed database operations.
    pub delay: Option<Duration>,
}

/// Bitcoin node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BitcoinConfig {
    /// Bitcoin RPC URL
    pub rpc_url: String,
    /// Bitcoin RPC username
    pub rpc_user: String,
    /// Bitcoin RPC password
    pub rpc_password: String,
    /// Connection string used in `bitcoin.conf => zmqpubrawblock`.
    // TODO(STR-2662): We should be able to work with `hashblock_connection_string` since ASM
    // runner used btc-client to fetch the full block. We don't use it here since the BlockEvent is
    // emitted only on the rawblock connection. Fix that.
    pub rawblock_connection_string: String,
    /// Retry policy applied to Bitcoin RPC calls. This is the *outer* retry
    /// layer; [`bitcoind_async_client::Client`] has its own retry loop beneath
    /// with defaults `max_retries=3`, `retry_interval=1000ms`, `timeout=30s`.
    ///
    /// Two things to know about the inner layer that motivate this outer one:
    ///
    /// - It is **narrow** — only `BitreqError` variants that pass `is_error_recoverable` (IO
    ///   errors, Rustls connection failures, malformed-chunk parse errors) get retried. HTTP
    ///   non-success status, JSON-RPC `Server` errors, redirects, body-size limits, and
    ///   `BitreqError::Other` bypass it entirely. A bitcoind that's restarting and replies with a
    ///   503 gets no inner retry at all.
    /// - It is **brief**. The inner loop sleeps *between* attempts, not before the first or after
    ///   the last. And note that the inner `max_retries` is actually the **total attempt cap**,
    ///   despite the name — `max_retries=3` means 3 attempts, not 3 retries on top of an initial
    ///   try. So a rapidly-failing recoverable error walks through: try → fail → sleep 1 s → try →
    ///   fail → sleep 1 s → try → fail → return `MaxRetriesExceeded`. Total inner wait: 2 × 1 s =
    ///   2 s. Too short to ride out anything beyond momentary glitches.
    ///
    /// The outer retry retries *every* `ClientError` from the inner layer,
    /// so transient transport hiccups get an extra ~2 s buffer from the
    /// inner retries inside a single outer attempt, and everything else
    /// (RPC errors, timeouts, redirects, …) still falls under the
    /// exponential schedule here. Worst-case duration of one outer attempt
    /// against a hung bitcoind: 3 × 30 s timeout + 2 × 1 s inner gap ≈ 92 s.
    #[serde(default)]
    pub retry_config: RetryConfig,
}
