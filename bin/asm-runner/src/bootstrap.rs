use std::sync::Arc;

use anyhow::Result;
use bitcoind_async_client::{Auth, Client};
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
    prover::{InputBuilder, ProofOrchestrator},
    rpc_server::run_rpc_server,
    storage::create_storage,
    worker_context::AsmWorkerContext,
};
pub(crate) async fn bootstrap(
    config: AsmRpcConfig,
    params: AsmParams,
    executor: TaskExecutor,
) -> Result<()> {
    // 1. Create storage
    let (state_db, mmr_db) = create_storage(&config.database)?;

    // 2. Connect to Bitcoin node
    let bitcoin_client = Arc::new(connect_bitcoin(&config.bitcoin).await?);

    // 3. Create our simplified BridgeWorkerContext
    let runtime_handle = Handle::current();
    let worker_context = AsmWorkerContext::new(
        runtime_handle.clone(),
        bitcoin_client.clone(),
        state_db.clone(),
        mmr_db.clone(),
    );

    // 4. Launch ASM worker
    let asm_worker = AsmWorkerBuilder::new()
        .with_context(worker_context)
        .with_asm_params(Arc::new(params.clone()))
        .with_asm_spec(StrataAsmSpec)
        .launch(&executor)?;

    // 5. Compute the starting height for the block watcher.
    let start_height = match asm_worker.monitor().get_current().cur_block {
        Some(blk) => blk.height(),
        None => params.anchor.block.height() + 1,
    };
    let asm_worker = Arc::new(asm_worker);

    // 6. Optionally create the proof channel and spawn the orchestrator
    let (proof_tx, proof_db_for_rpc) = if let Some(orch_config) = config.orchestrator {
        let (tx, rx) = mpsc::unbounded_channel();

        let proof_db = SledProofDb::open(&orch_config.proof_db_path)?;
        let proof_db_clone = proof_db.clone();

        #[cfg(feature = "sp1")]
        let (asm, moho) = {
            use std::fs;

            use strata_asm_sp1_guest_builder::{ASM_ELF_PATH, MOHO_ELF_PATH};
            use zkaleido_sp1_host::SP1Host;
            let asm_elf = fs::read(ASM_ELF_PATH)
                .unwrap_or_else(|err| panic!("failed to read guest elf at {ASM_ELF_PATH}: {err}"));
            let moho_elf = fs::read(MOHO_ELF_PATH)
                .unwrap_or_else(|err| panic!("failed to read guest elf at {MOHO_ELF_PATH}: {err}"));
            (SP1Host::init(&asm_elf), SP1Host::init(&moho_elf))
        };

        #[cfg(not(feature = "sp1"))]
        let (asm, moho) = {
            use moho_recursive_proof::MohoRecursiveProgram;
            use strata_asm_proof_impl::program::AsmStfProofProgram;
            (
                AsmStfProofProgram::native_host(),
                MohoRecursiveProgram::native_host(),
            )
        };

        let input_builder = InputBuilder::new(
            state_db.clone(),
            bitcoin_client.clone(),
            proof_db.clone(),
            params.anchor.block,
        );
        let mut orchestrator =
            ProofOrchestrator::new(proof_db, asm, moho, orch_config, input_builder, rx);

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

        (Some(tx), Some(proof_db_clone))
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
            start_height as u64,
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
            asm_worker,
            bitcoin_client,
            proof_db_for_rpc,
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
