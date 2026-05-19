//! Configuration structures for ASM RPC server

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::prover::config::OrchestratorConfig;

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
    /// Logging configuration. Omit the `[logging]` section to accept defaults
    /// (stdout, compact format, `RUST_LOG`-driven filter).
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Logging configuration mirroring `strata_logging::LoggingInitConfig`.
///
/// All fields are optional; missing fields fall back to `strata-logging` defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct LoggingConfig {
    /// Optional service label appended to the service name (e.g. `"prod"`, `"dev"`).
    pub service_label: Option<String>,
    /// OpenTelemetry OTLP collector gRPC endpoint. When set, OTLP export is enabled
    /// and the tracing-to-metrics bridge is turned on automatically.
    pub otlp_url: Option<String>,
    /// Directory to write rolling log files into. When unset, file logging is disabled.
    pub log_dir: Option<PathBuf>,
    /// Filename prefix for rolling log files. Falls back to the binary's default prefix.
    pub log_file_prefix: Option<String>,
    /// Use JSON output format instead of the compact text format.
    pub json_format: Option<bool>,
    /// Extra `EnvFilter` directives applied before `RUST_LOG` (e.g. to silence noisy
    /// dependencies). Empty when omitted.
    pub extra_filter_directives: Vec<String>,
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
    /// Optional retry count for failed requests
    pub retry_count: Option<u64>,
    /// Optional retry interval
    pub retry_interval: Option<Duration>,
    /// Connection string used in `bitcoin.conf => zmqpubrawblock`.
    // TODO(STR-2662): We should be able to work with `hashblock_connection_string` since ASM
    // runner used btc-client to fetch the full block. We don't use it here since the BlockEvent is
    // emitted only on the rawblock connection. Fix that.
    pub rawblock_connection_string: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A `[logging]` section that only sets `otlp_url` must deserialize cleanly
    // and leave every other field at its default — historically the missing
    // `extra_filter_directives` triggered `missing field` errors.
    #[test]
    fn logging_config_partial_section_uses_defaults() {
        let toml_src = r#"
            [rpc]
            host = "127.0.0.1"
            port = 8000

            [database]
            path = "/tmp/asm-db"

            [bitcoin]
            rpc_url = "http://localhost:18443"
            rpc_user = "user"
            rpc_password = "pass"
            rawblock_connection_string = "tcp://127.0.0.1:28332"

            [logging]
            otlp_url = "http://localhost:4317"
        "#;

        let config: AsmRpcConfig = toml::from_str(toml_src).expect("should parse");

        assert_eq!(
            config.logging.otlp_url.as_deref(),
            Some("http://localhost:4317")
        );
        assert!(config.logging.service_label.is_none());
        assert!(config.logging.log_dir.is_none());
        assert!(config.logging.log_file_prefix.is_none());
        assert!(config.logging.json_format.is_none());
        assert!(config.logging.extra_filter_directives.is_empty());
    }

    // Omitting the entire `[logging]` table must also be a clean parse.
    #[test]
    fn logging_section_optional() {
        let toml_src = r#"
            [rpc]
            host = "127.0.0.1"
            port = 8000

            [database]
            path = "/tmp/asm-db"

            [bitcoin]
            rpc_url = "http://localhost:18443"
            rpc_user = "user"
            rpc_password = "pass"
            rawblock_connection_string = "tcp://127.0.0.1:28332"
        "#;

        let config: AsmRpcConfig = toml::from_str(toml_src).expect("should parse");

        assert!(config.logging.otlp_url.is_none());
        assert!(config.logging.extra_filter_directives.is_empty());
    }
}
