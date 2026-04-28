use std::sync::Arc;

use anyhow::Result;
use bitcoind_async_client::{Auth, Client};
use strata_asm_params::AsmParams;
use strata_asm_proof_db::{SledMohoStateDb, SledProofDb};
use strata_asm_spec::StrataAsmSpec;
use strata_asm_worker::AsmWorkerBuilder;
use strata_tasks::TaskExecutor;
use tokio::{
    runtime::{Builder as RuntimeBuilder, Handle},
    sync::mpsc,
    task::{self, LocalSet},
};

use crate::{
    block_watcher::drive_asm_from_bitcoin,
    config::{AsmRpcConfig, BitcoinConfig},
    prover::{InputBuilder, ProofBackend, ProofOrchestrator},
    rpc_server::{AsmProofRpcDeps, run_rpc_server},
    storage::create_storage,
    worker_context::{AsmWorkerContext, MohoStorage},
};
pub(crate) async fn bootstrap(
    config: AsmRpcConfig,
    params: AsmParams,
    executor: TaskExecutor,
) -> Result<()> {
    // 1. Create storage
    let (state_db, mmr_db, export_entries_db) = create_storage(&config.database)?;

    // 2. Connect to Bitcoin node
    let bitcoin_client = Arc::new(connect_bitcoin(&config.bitcoin).await?);

    // 3. If the orchestrator is configured, open proof storage and build the proof backend up front
    //    so the worker can receive the moho-state db and the asm predicate. The worker owns
    //    moho-state writes (including the genesis seed) — see [`MohoStorage`].
    let runtime_handle = Handle::current();
    let orch_prep = if let Some(orch_config) = config.orchestrator {
        let sled_db = sled::open(&orch_config.proof_db_path)?;
        let proof_db = SledProofDb::open(&sled_db)?;
        let moho_state_db = SledMohoStateDb::open(&sled_db)?;
        let backend = ProofBackend::new()?;
        Some((orch_config, proof_db, moho_state_db, backend))
    } else {
        None
    };

    // 4. Create the worker context, wiring moho storage when available.
    let moho_storage = orch_prep.as_ref().map(|(_, _, db, backend)| MohoStorage {
        db: db.clone(),
        asm_predicate: backend.asm_predicate.clone(),
    });
    let export_entries_for_worker = orch_prep.as_ref().map(|_| export_entries_db.clone());
    let worker_context = AsmWorkerContext::new(
        runtime_handle.clone(),
        bitcoin_client.clone(),
        state_db.clone(),
        mmr_db.clone(),
        export_entries_for_worker,
        moho_storage,
    );

    // 5. Launch ASM worker
    let asm_worker = AsmWorkerBuilder::new()
        .with_context(worker_context)
        .with_asm_spec(StrataAsmSpec)
        .with_params(params.clone())
        .launch(&executor)?;

    // 6. Compute the starting height for the block watcher.
    let start_height = match asm_worker.monitor().get_current().cur_block {
        Some(blk) => blk.height(),
        None => params.anchor.block.height() + 1,
    };
    let asm_worker = Arc::new(asm_worker);

    // 7. Finish orchestrator wiring if it was configured.
    let (proof_tx, proof_rpc_deps) = if let Some((orch_config, proof_db, moho_state_db, backend)) = orch_prep {
        let (tx, rx) = mpsc::unbounded_channel();
        let rpc_deps = AsmProofRpcDeps {
            proof_db: proof_db.clone(),
            moho_state_db: moho_state_db.clone(),
            export_entries_db: export_entries_db.clone(),
        };

        let ProofBackend {
            asm_host,
            moho_host,
            asm_predicate,
            moho_predicate,
        } = backend;

        let input_builder = InputBuilder::new(
            state_db.clone(),
            bitcoin_client.clone(),
            proof_db.clone(),
            moho_state_db,
            params.anchor.block,
            asm_predicate,
            moho_predicate,
        );
        let mut orchestrator = ProofOrchestrator::new(
            proof_db,
            asm_host,
            moho_host,
            orch_config,
            input_builder,
            rx,
        );

        // ZkVmRemoteProver is !Send (#[async_trait(?Send)]), so the orchestrator
        // future cannot be spawned on a multi-threaded runtime directly. We run it
        // on a dedicated thread with a single-threaded runtime + LocalSet.
        executor.spawn_critical_async_with_shutdown(
            "proof_orchestrator",
            move |shutdown| async move {
                task::spawn_blocking(move || {
                    let rt = RuntimeBuilder::new_current_thread().enable_all().build()?;
                    let local = LocalSet::new();
                    rt.block_on(local.run_until(async move { orchestrator.run(shutdown).await }))
                })
                .await?
            },
        );

        (Some(tx), Some(rpc_deps))
    } else {
        (None, None)
    };

    // 8. Spawn block watcher as a critical task.
    let asm_worker_for_driver = asm_worker.clone();
    let bitcoin_config = config.bitcoin.clone();
    let bitcoin_client_for_driver = bitcoin_client.clone();
    executor.spawn_critical_async_with_shutdown("block_watcher", move |shutdown| {
        drive_asm_from_bitcoin(
            bitcoin_config,
            bitcoin_client_for_driver,
            asm_worker_for_driver,
            start_height as u64,
            proof_tx,
            shutdown,
        )
    });

    // 9. Spawn RPC server as a critical task
    let rpc_host = config.rpc.host.clone();
    let rpc_port = config.rpc.port;
    executor.spawn_critical_async_with_shutdown("rpc_server", move |shutdown| {
        run_rpc_server(
            state_db,
            asm_worker,
            bitcoin_client,
            proof_rpc_deps,
            rpc_host,
            rpc_port,
            shutdown,
        )
    });

    Ok(())
}

/// Connect to Bitcoin node
async fn connect_bitcoin(config: &BitcoinConfig) -> Result<Client> {
    let client = Client::new(
        config.rpc_url.clone(),
        Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        None, // timeout
        config.retry_count,
        config.retry_interval.map(|d| d.as_millis() as u64),
    )?;

    Ok(client)
}
