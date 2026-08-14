//! Configuration structures for ASM RPC server

use std::{fmt, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use strata_asm_prover_worker::OrchestratorConfig;
use strata_logging::LoggingInitConfig;

use crate::retry::RetryConfig;

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
    pub logging: LoggingInitConfig,
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RpcConfig {
    /// Host address to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
}

/// Database configuration.
///
/// The runner persists into separate sled databases: the ASM DB (anchor
/// states, aux data, manifests, manifest-hash MMR) and the Moho DB (Moho
/// state snapshots, export entries). The proof DB is configured with the
/// orchestrator that owns it — see
/// [`OrchestratorConfig::proof_db_path`](strata_asm_prover_worker::OrchestratorConfig).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseConfig {
    /// SledDB path (directory) for the ASM stores.
    pub asm_path: PathBuf,
    /// SledDB path (directory) for the Moho stores.
    pub moho_path: PathBuf,
    /// Optional number of threads for database operations.
    pub num_threads: Option<usize>,
    /// Optional number of retries for failed database operations.
    pub retry_count: Option<u16>,
    /// Optional number between retries for failed database operations.
    pub delay: Option<Duration>,
}

/// Bitcoin node configuration
///
/// `Debug` is implemented by hand so `rpc_password` is never printed. Startup
/// logs the whole [`AsmRpcConfig`], and those records reach stdout, rolling
/// files, and the OTLP collector, so a derived `Debug` would copy the
/// credential to every enabled sink.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BitcoinConfig {
    /// Bitcoin RPC URL
    pub rpc_url: String,
    /// Bitcoin RPC username
    pub rpc_user: String,
    /// Bitcoin RPC password
    pub rpc_password: String,
    /// Connection string used in `bitcoin.conf => zmqpubhashblock`.
    ///
    /// The watcher only needs the new block's hash to drive the worker (which
    /// re-fetches the full block by RPC), so it subscribes to `hashblock`
    /// rather than shipping every full block over `rawblock`.
    pub hashblock_connection_string: String,
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

impl fmt::Debug for BitcoinConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinConfig")
            .field("rpc_url", &self.rpc_url)
            .field("rpc_user", &self.rpc_user)
            .field("rpc_password", &"<redacted>")
            .field(
                "hashblock_connection_string",
                &self.hashblock_connection_string,
            )
            .field("retry_config", &self.retry_config)
            .finish()
    }
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
            asm_path = "/tmp/asm-db"
            moho_path = "/tmp/moho-db"

            [bitcoin]
            rpc_url = "http://localhost:18443"
            rpc_user = "user"
            rpc_password = "pass"
            hashblock_connection_string = "tcp://127.0.0.1:28332"

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

    // Startup logs the whole config, so no debug rendering of it may carry the
    // Bitcoin RPC password — neither the leaf struct nor the parent that holds it.
    #[test]
    fn debug_redacts_bitcoin_rpc_password() {
        let toml_src = r#"
            [rpc]
            host = "127.0.0.1"
            port = 8000

            [database]
            asm_path = "/tmp/asm-db"
            moho_path = "/tmp/moho-db"

            [bitcoin]
            rpc_url = "http://localhost:18443"
            rpc_user = "user"
            rpc_password = "hunter2"
            hashblock_connection_string = "tcp://127.0.0.1:28332"
        "#;

        let config: AsmRpcConfig = toml::from_str(toml_src).expect("should parse");

        for rendered in [
            format!("{:?}", config.bitcoin),
            format!("{:#?}", config.bitcoin),
            format!("{config:?}"),
        ] {
            assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
            assert!(rendered.contains("<redacted>"));
        }

        // Non-secret fields stay visible — the point is a usable diagnostic, not a blank struct.
        let rendered = format!("{:?}", config.bitcoin);
        assert!(rendered.contains("http://localhost:18443"));
        assert!(rendered.contains("tcp://127.0.0.1:28332"));
    }

    // Omitting the entire `[logging]` table must also be a clean parse.
    #[test]
    fn logging_section_optional() {
        let toml_src = r#"
            [rpc]
            host = "127.0.0.1"
            port = 8000

            [database]
            asm_path = "/tmp/asm-db"
            moho_path = "/tmp/moho-db"

            [bitcoin]
            rpc_url = "http://localhost:18443"
            rpc_user = "user"
            rpc_password = "pass"
            hashblock_connection_string = "tcp://127.0.0.1:28332"
        "#;

        let config: AsmRpcConfig = toml::from_str(toml_src).expect("should parse");

        assert!(config.logging.otlp_url.is_none());
        assert!(config.logging.extra_filter_directives.is_empty());
    }
}
