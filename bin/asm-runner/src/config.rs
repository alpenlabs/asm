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
    /// layer; [`bitcoind_async_client::Client`] has its own narrow retry
    /// loop underneath that only covers transient transport hiccups and is
    /// brief enough to not ride out anything beyond a momentary glitch. The
    /// outer layer here is what carries us through longer outages (e.g. a
    /// bitcoind restart). Every `ClientError` from the inner layer is
    /// retried by this outer layer.
    #[serde(default)]
    pub retry_config: RetryConfig,
}
