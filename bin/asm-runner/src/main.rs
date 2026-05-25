//! ASM Runner Binary
//!
//! Standalone binary that runs the ASM (Anchor State Machine) STF and exposes an RPC API
//! for querying ASM state.

mod block_watcher;
mod bootstrap;
mod config;
mod prover;
mod retry;
mod rpc_server;
mod storage;
mod worker_context;

use std::{fs::read_to_string, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;
use strata_asm_params::AsmParams;
use strata_logging::{LoggingInitConfig, finalize, init_logging_from_config};
use strata_tasks::TaskManager;
use tokio::runtime::{Builder, Handle};
use tracing::{error, info};
use zkaleido_native_adapter as _;

use crate::{
    bootstrap::bootstrap,
    config::{AsmRpcConfig, LoggingConfig},
};

/// Timeout for graceful shutdown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// ASM Runner - Run the ASM STF and expose RPC API
#[derive(Parser, Debug)]
#[command(name = "asm-runner")]
#[command(about = "ASM runner for executing ASM STF", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Path to ASM params JSON file
    #[arg(short, long, default_value = "asm-params.json")]
    params: PathBuf,
}

fn main() {
    // 1. Parse CLI args
    let cli = Cli::parse();

    // 2. Load configuration
    let config = load_config(&cli.config).expect("Failed to load config");

    // 3. Load ASM params
    let params = load_params(&cli.params).expect("Failed to load ASM params");

    // 4. Create tokio runtime
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    // 5. Initialize logging.
    init_logging(runtime.handle(), &config.logging);

    info!(
        "Starting ASM RPC server with config: {:?}, params: {:?}",
        config, params
    );

    // 6. Create task manager and start signal listeners
    let task_manager = TaskManager::new(runtime.handle().clone());
    task_manager.start_signal_listeners();
    let executor = task_manager.create_executor();

    // 7. Spawn the main async initialization and server logic as a critical task
    let executor_clone = executor.clone();
    executor.spawn_critical_async("main_task", async move {
        bootstrap(config, params, executor_clone).await
    });

    // 8. Monitor all tasks and handle shutdown. Flush OTLP on both paths so a crash signal still
    //    reaches the collector.
    match task_manager.monitor(Some(SHUTDOWN_TIMEOUT)) {
        Ok(()) => {
            info!("ASM RPC server shutdown complete");
            finalize();
        }
        Err(e) => {
            error!("ASM RPC server crashed: {e:?}");
            finalize();
            panic!("ASM RPC server crashed: {e:?}");
        }
    }
}

/// Load ASM parameters
fn load_params(params_path: &PathBuf) -> Result<AsmParams> {
    let contents = read_to_string(params_path)?;
    let params: AsmParams = serde_json::from_str(&contents)?;
    Ok(params)
}

/// Load configuration from file
fn load_config(path: &PathBuf) -> Result<AsmRpcConfig> {
    let contents = read_to_string(path)?;
    let config: AsmRpcConfig = toml::from_str(&contents)?;
    Ok(config)
}

// The OTLP exporter is built via the Tokio reactor, so init must happen inside
// a runtime context — entering the handle for the duration of this call is
// enough; the guard does not need to live past initialization.
fn init_logging(rt: &Handle, config: &LoggingConfig) {
    let _guard = rt.enter();
    let extra_filter_directives: Vec<&str> = config
        .extra_filter_directives
        .iter()
        .map(String::as_str)
        .collect();
    init_logging_from_config(LoggingInitConfig {
        service_base_name: "asm-runner",
        service_label: config.service_label.as_deref(),
        otlp_url: config.otlp_url.as_deref(),
        log_dir: config.log_dir.as_ref(),
        log_file_prefix: config.log_file_prefix.as_deref(),
        json_format: config.json_format,
        default_log_prefix: "asm-runner",
        extra_filter_directives: &extra_filter_directives,
    });
}
