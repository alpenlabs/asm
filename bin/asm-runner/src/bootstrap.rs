use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoind_async_client::{Auth, Client};
use strata_asm_moho_worker::MohoWorkerBuilder;
use strata_asm_params::AsmParams;
use strata_asm_prover_worker::{
    AsmArtifactConfig, AsmProofHost, InputBuilder, ProofBackend, ProofHost, ProverResult,
    ProverWorkerBuilder, load_spec_host,
};
use strata_asm_spec::{
    StrataAsmSpec,
    host::{CompiledSpec, build_execution_registry},
};
use strata_asm_worker::AsmWorkerBuilder;
use strata_tasks::TaskExecutor;
use tokio::{runtime::Handle, task};

use crate::{
    bitcoin_client::RetryingBitcoinClient,
    block_watcher::drive_asm_from_bitcoin,
    config::{AsmRpcConfig, BitcoinConfig},
    moho_context::MohoWorkerContextImpl,
    prover_context::AsmProverContext,
    rpc_server::{AsmProofRpcDeps, run_rpc_server},
    storage::{
        AsmStorage, MohoStorage, create_asm_storage, create_moho_storage, create_proof_storage,
    },
    worker_context::AsmWorkerContext,
};
pub(crate) async fn bootstrap(
    config: AsmRpcConfig,
    params: AsmParams,
    executor: TaskExecutor,
) -> Result<()> {
    let registry = build_execution_registry(
        config
            .execution
            .targets
            .iter()
            .map(|entry| (entry.predicate.clone(), entry.spec_id)),
    )?;
    let genesis_predicate = registry
        .predicate(config.execution.genesis_spec_id)
        .context("execution.genesis_spec_id is not listed in [[execution.targets]]")?
        .clone();
    let genesis_spec = CompiledSpec::resolve(config.execution.genesis_spec_id)?;
    let genesis_state = genesis_spec.construct_genesis_state(&params);

    // 1. Create storage. The ASM and Moho stores live in two separate sled DBs; the proof DB is
    //    opened with the orchestrator that owns it (step 3).
    let AsmStorage {
        state_db,
        aux_db,
        manifest_db,
        mmr_db,
    } = create_asm_storage(&config.database.asm_path)?;
    let MohoStorage {
        state_db: moho_state_db,
        export_entries_db,
    } = create_moho_storage(&config.database.moho_path)?;

    // 2. Connect to Bitcoin node
    let bitcoin_client = Arc::new(RetryingBitcoinClient::new(
        connect_bitcoin(&config.bitcoin).await?,
        &config.bitcoin.retry_config,
    ));

    // 3. If the orchestrator is configured, open proof storage and build the proof backend up front
    //    so a misconfigured artifact fails before any worker starts.
    let runtime_handle = Handle::current();
    let orch_prep = if let Some(orch_config) = config.orchestrator {
        let proof_db = create_proof_storage(&orch_config.proof_db_path)?;
        // The execution registry is the single record of which spec each predicate implements.
        let mut asm_hosts = Vec::with_capacity(orch_config.asm_artifacts.len());
        for artifact in &orch_config.asm_artifacts {
            let spec_id = registry
                .resolve(&artifact.predicate)
                .context(
                    "orchestrator.asm_artifacts predicate is not listed in [[execution.targets]]",
                )?
                .spec_id();
            asm_hosts.push(load_asm_host(CompiledSpec::resolve(spec_id)?, artifact).await?);
        }
        let backend = ProofBackend::new(&orch_config.moho, asm_hosts).await?;
        Some((orch_config, proof_db, backend))
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
            .with_genesis(genesis_state, genesis_predicate.clone())
            .with_registry(registry)
            .launch(&executor)
    })?;

    let asm_worker = Arc::new(asm_worker);

    // 6. Finish orchestrator wiring if it was configured.
    let proof_rpc_deps = if let Some((orch_config, proof_db, backend)) = orch_prep {
        let ProofBackend {
            asm_hosts,
            moho_host,
            moho_predicate,
        } = backend;

        // Spin the Moho worker off onto its own service task, driven by the ASM
        // worker's per-block commit stream. It derives each block's MohoState
        // (and the export-entry leaves its ExportState MMR commits to) from the
        // anchor state the ASM worker committed, and persists both to the same
        // stores the orchestrator and RPC read. Subscribe before the block
        // watcher is spawned (step 7): the subscription has no replay, so a later
        // subscriber would miss already-committed blocks. The genesis Moho state
        // is seeded from the ASM genesis anchor during launch.
        let moho_context = MohoWorkerContextImpl::new(
            runtime_handle.clone(),
            bitcoin_client.clone(),
            state_db.clone(),
            manifest_db.clone(),
            moho_state_db.clone(),
            export_entries_db.clone(),
        );
        let moho_worker = MohoWorkerBuilder::new()
            .with_context(moho_context)
            .with_subscription(asm_worker.subscribe_blocks())
            .with_genesis_block(params.anchor.block)
            .with_asm_predicate(genesis_predicate)
            .launch(&executor)
            .await?;

        // The prover context wires the proof store, moho-state store, ASM
        // anchor-state store, aux-data store, and Bitcoin client into the
        // worker's traits. Clone the two stores the RPC handlers also read from
        // before the context takes ownership.
        let rpc_proof_db = proof_db.clone();
        let rpc_moho_state_db = moho_state_db.clone();
        let prover_ctx = AsmProverContext::new(
            proof_db,
            moho_state_db,
            state_db.clone(),
            aux_db.clone(),
            bitcoin_client.clone(),
        );
        let input_builder = InputBuilder::new(params.anchor.block, moho_predicate);

        // Drive the prover from the *Moho* worker's commit stream, not the ASM
        // worker's: the Moho worker emits a block only after it has persisted
        // that block's MohoState, so any block the prover sees here already has
        // its MohoState available for proof-input assembly. This serializes the
        // ASM → Moho → prover chain and removes the race that existed when the
        // prover and the Moho worker subscribed to the ASM stream independently.
        //
        // Subscribe before the block watcher (spawned below) starts feeding the
        // ASM worker. The stream has no replay buffer, but commits only flow once
        // the watcher hands the ASM worker blocks, so subscribing here misses
        // nothing.
        let block_subscription = moho_worker.subscribe_blocks();

        let prover_handle = ProverWorkerBuilder::new()
            .with_context(prover_ctx)
            .with_hosts(asm_hosts, moho_host)
            .with_config(orch_config)
            .with_input_builder(input_builder)
            .with_block_subscription(block_subscription)
            .launch(&executor)
            .await?;

        Some(AsmProofRpcDeps {
            proof_db: rpc_proof_db,
            prover_handle: Arc::new(prover_handle),
            moho_state_db: rpc_moho_state_db,
            export_entries_db,
        })
    } else {
        None
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
            params,
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

/// Loads the proof host for `artifact` under its compiled spec, checked against the
/// configured predicate.
///
/// Kept beside the runner rather than in `strata_asm_spec::host`, so native callers of that
/// catalog take no prover dependency.
async fn load_asm_host(
    spec: CompiledSpec,
    artifact: &AsmArtifactConfig,
) -> ProverResult<AsmProofHost<ProofHost>> {
    match spec {
        CompiledSpec::V0 => load_spec_host(artifact, StrataAsmSpec).await,
    }
}
