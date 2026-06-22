use std::sync::Arc;

use anyhow::Result;
use bitcoind_async_client::{Auth, Client};
use strata_asm_moho_storage::SledMohoStateDb;
use strata_asm_moho_worker::MohoWorkerBuilder;
use strata_asm_params::AsmParams;
use strata_asm_proof_db::SledProofDb;
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
    moho_context::MohoWorkerContextImpl,
    prover::{InputBuilder, ProofBackend, ProofOrchestrator},
    rpc_server::{AsmProofRpcDeps, run_rpc_server},
    storage::{Storage, create_storage},
    worker_context::AsmWorkerContext,
};
pub(crate) async fn bootstrap(
    config: AsmRpcConfig,
    params: AsmParams,
    executor: TaskExecutor,
) -> Result<()> {
    // 1. Create storage
    let Storage {
        state_db,
        aux_db,
        manifest_db,
        mmr_db,
        export_entries_db,
    } = create_storage(&config.database)?;

    // 2. Connect to Bitcoin node
    let bitcoin_client = Arc::new(connect_bitcoin(&config.bitcoin).await?);

    // 3. If the orchestrator is configured, open proof storage and build the proof backend up front
    //    so the Moho worker and orchestrator can receive the moho-state db and the asm predicate.
    let runtime_handle = Handle::current();
    let orch_prep = if let Some(orch_config) = config.orchestrator {
        let sled_db = sled::open(&orch_config.proof_db_path)?;
        let proof_db = SledProofDb::open(&sled_db)?;
        let moho_state_db = SledMohoStateDb::open(&sled_db)?;
        let backend = ProofBackend::new(&orch_config.backend).await?;
        Some((orch_config, proof_db, moho_state_db, backend))
    } else {
        None
    };

    // 4. Create the ASM worker context. Moho state and the export-entries index are no longer
    //    materialized here; a dedicated Moho worker derives both from each ASM commit (step 7).
    //
    // The worker aligns the DB-side ASM manifest MMR with L1 heights during
    // startup (`ManifestMmrStore::prefill_manifest_mmr`), so no prefill is
    // needed here.
    let worker_context = AsmWorkerContext::new(
        runtime_handle.clone(),
        bitcoin_client.clone(),
        &config.bitcoin.retry_config,
        state_db.clone(),
        aux_db.clone(),
        manifest_db.clone(),
        mmr_db.clone(),
    );

    // 5. Launch ASM worker.
    //
    // `launch` builds the worker state synchronously, and that now includes validating the
    // anchor against L1 — which drives blocking `WorkerContext` RPC calls (`block_on`). We are
    // on a runtime worker thread here, so wrap the build in `block_in_place` to allow blocking;
    // the worker's own loop runs on a dedicated sync thread where blocking is already fine.
    let asm_worker = task::block_in_place(|| {
        AsmWorkerBuilder::new()
            .with_context(worker_context)
            .with_asm_spec(StrataAsmSpec)
            .with_params(params.clone())
            .launch(&executor)
    })?;

    let asm_worker = Arc::new(asm_worker);

    // 6. Finish orchestrator wiring if it was configured.
    let (proof_tx, proof_rpc_deps) = if let Some((orch_config, proof_db, moho_state_db, backend)) =
        orch_prep
    {
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

        // Spin the Moho worker off onto its own service task, driven by the ASM
        // worker's per-block commit stream. It derives each block's MohoState
        // (and the export-entry leaves its ExportState MMR commits to) from the
        // anchor state the ASM worker committed, and persists both to the same
        // stores the orchestrator and RPC read. Subscribe before the block
        // watcher is spawned (step 8): the subscription has no replay, so a later
        // subscriber would miss already-committed blocks. The genesis Moho state
        // is seeded from the ASM genesis anchor during launch.
        let moho_context = MohoWorkerContextImpl::new(
            runtime_handle.clone(),
            bitcoin_client.clone(),
            &config.bitcoin.retry_config,
            state_db.clone(),
            manifest_db.clone(),
            moho_state_db.clone(),
            export_entries_db.clone(),
        );
        let _moho_worker = MohoWorkerBuilder::new()
            .with_context(moho_context)
            .with_subscription(asm_worker.subscribe_blocks())
            .with_genesis_block(params.anchor.block)
            .with_asm_predicate(asm_predicate.clone())
            .launch(&executor)
            .await?;

        let input_builder = InputBuilder::new(
            state_db.clone(),
            aux_db.clone(),
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

    // 7. Spawn block watcher as a critical task.
    let asm_worker_for_driver = asm_worker.clone();
    let bitcoin_config = config.bitcoin.clone();
    let bitcoin_client_for_driver = bitcoin_client.clone();
    executor.spawn_critical_async_with_shutdown("block_watcher", move |shutdown| {
        drive_asm_from_bitcoin(
            bitcoin_config,
            bitcoin_client_for_driver,
            asm_worker_for_driver,
            proof_tx,
            shutdown,
        )
    });

    // 8. Spawn RPC server as a critical task
    let rpc_host = config.rpc.host.clone();
    let rpc_port = config.rpc.port;
    executor.spawn_critical_async_with_shutdown("rpc_server", move |shutdown| {
        run_rpc_server(
            state_db,
            manifest_db,
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

/// Connect to Bitcoin node.
///
/// All three `Option` parameters are passed as `None` so
/// `bitcoind-async-client` applies its own defaults for `max_retries`,
/// `retry_interval`, and `timeout`. See [`BitcoinConfig::retry_config`]
/// for how this inner layer composes with the outer retry wrapper.
async fn connect_bitcoin(config: &BitcoinConfig) -> Result<Client> {
    let client = Client::new(
        config.rpc_url.clone(),
        Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        None,
        None,
        None,
    )?;

    Ok(client)
}
