//! RPC server implementation for ASM queries

use std::{fmt::Display, sync::Arc, time::Instant};

use anyhow::Result;
use asm_storage::{SledAsmManifestDb, SledAsmStateDb};
use async_trait::async_trait;
use bitcoin::BlockHash;
use bitcoind_async_client::{Client, traits::Reader};
use jsonrpsee::{
    core::RpcResult,
    server::ServerBuilder,
    types::{ErrorObject, ErrorObjectOwned},
};
use moho_types::MohoState;
use ssz::{Decode, Encode};
use strata_asm_bridge_types::SafeHarbour;
use strata_asm_checkpoint_types::CheckpointTip;
use strata_asm_common::{AnchorState, AsmManifest};
use strata_asm_moho_storage::{
    ExportProofError, SledExportEntriesDb, SledMohoStateDb, build_export_entry_mmr_proof,
};
use strata_asm_params::AsmParams;
use strata_asm_proto_bridge::{AssignmentEntry, BridgeStateV1, DepositEntry};
use strata_asm_proto_bridge_txs::BRIDGE_SUBPROTOCOL_ID;
use strata_asm_proto_checkpoint::CheckpointState;
use strata_asm_proto_checkpoint_txs::CHECKPOINT_SUBPROTOCOL_ID;
use strata_asm_prover_storage::{ProofDb, SledProofDb};
use strata_asm_prover_types::{AsmProof, L1Range, MohoProof, ProverStatus};
use strata_asm_prover_worker::ProverWorkerHandle;
use strata_asm_rpc::traits::{
    AsmControlApiServer, AsmMohoApiServer, AsmProofApiServer, AsmStateApiServer,
};
use strata_asm_worker::{AsmWorkerHandle, AsmWorkerStatus};
use strata_btc_types::BlockHashExt;
use strata_identifiers::L1BlockCommitment;
use strata_tasks::ShutdownGuard;
use tracing::{info, warn};

/// Convert any error to an RPC error
fn to_rpc_error(e: impl Display) -> ErrorObjectOwned {
    ErrorObject::owned(-32000, e.to_string(), None::<()>)
}

async fn to_block_commitment(
    bitcoin_client: &Client,
    block_hash: BlockHash,
) -> anyhow::Result<L1BlockCommitment> {
    let block_id = block_hash.to_l1_block_id();
    let height = bitcoin_client.get_block_height(&block_hash).await? as u32;
    Ok(L1BlockCommitment::new(height, block_id))
}

/// Always-on ASM RPC handlers backed by the ASM state DB and worker status.
#[derive(Clone)]
pub(crate) struct AsmRpcServer {
    state_db: Arc<SledAsmStateDb>,
    manifest_db: Arc<SledAsmManifestDb>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
    params: Arc<AsmParams>,
    /// Monotonic start instant, used to compute uptime for the control API.
    start_time: Instant,
}

impl AsmRpcServer {
    pub(crate) fn new(
        state_db: Arc<SledAsmStateDb>,
        manifest_db: Arc<SledAsmManifestDb>,
        asm_worker: Arc<AsmWorkerHandle>,
        bitcoin_client: Arc<Client>,
        params: AsmParams,
    ) -> Self {
        Self {
            state_db,
            manifest_db,
            asm_worker,
            bitcoin_client,
            params: Arc::new(params),
            start_time: Instant::now(),
        }
    }

    async fn get_bridge_state(&self, block_hash: BlockHash) -> RpcResult<Option<BridgeStateV1>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;
        let state = self.state_db.get(&commitment).map_err(to_rpc_error)?;
        match state {
            Some(state) => {
                let bridge_state = state
                    .find_section(BRIDGE_SUBPROTOCOL_ID)
                    .expect("bridge subprotocol should be enabled");

                let bridge_state = BridgeStateV1::from_ssz_bytes(&bridge_state.data)
                    .expect("bridge state deserialization should be infallible");

                Ok(Some(bridge_state))
            }
            None => Ok(None),
        }
    }

    async fn get_checkpoint_state(
        &self,
        block_hash: BlockHash,
    ) -> RpcResult<Option<CheckpointState>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;
        let state = self.state_db.get(&commitment).map_err(to_rpc_error)?;
        match state {
            Some(state) => {
                let checkpoint_state = state
                    .find_section(CHECKPOINT_SUBPROTOCOL_ID)
                    .expect("checkpoint subprotocol should be enabled");

                let checkpoint_state = CheckpointState::from_ssz_bytes(&checkpoint_state.data)
                    .expect("checkpoint state deserialization should be infallible");

                Ok(Some(checkpoint_state))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl AsmControlApiServer for AsmRpcServer {
    async fn get_uptime(&self) -> RpcResult<u64> {
        Ok(self.start_time.elapsed().as_secs())
    }

    async fn get_status(&self) -> RpcResult<AsmWorkerStatus> {
        Ok(self.asm_worker.monitor().get_current())
    }

    async fn get_params(&self) -> RpcResult<AsmParams> {
        Ok((*self.params).clone())
    }
}

#[async_trait]
impl AsmStateApiServer for AsmRpcServer {
    async fn get_assignments(&self, block_hash: BlockHash) -> RpcResult<Vec<AssignmentEntry>> {
        match self.get_bridge_state(block_hash).await? {
            Some(bridge_state) => Ok(bridge_state.assignments().assignments().to_vec()),
            None => Ok(vec![]),
        }
    }

    async fn get_deposits(&self, block_hash: BlockHash) -> RpcResult<Vec<DepositEntry>> {
        match self.get_bridge_state(block_hash).await? {
            Some(bridge_state) => Ok(bridge_state.deposits().deposits().cloned().collect()),
            None => Ok(vec![]),
        }
    }

    async fn get_safe_harbour(&self, block_hash: BlockHash) -> RpcResult<Option<SafeHarbour>> {
        match self.get_bridge_state(block_hash).await? {
            Some(bridge_state) => Ok(Some(bridge_state.safe_harbour().clone())),
            None => Ok(None),
        }
    }

    async fn get_checkpoint_tip(&self, block_hash: BlockHash) -> RpcResult<Option<CheckpointTip>> {
        match self.get_checkpoint_state(block_hash).await? {
            Some(checkpoint_state) => Ok(Some(*checkpoint_state.verified_tip())),
            None => Ok(None),
        }
    }

    async fn get_anchor_state(&self, block_hash: BlockHash) -> RpcResult<Option<AnchorState>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;

        self.state_db.get(&commitment).map_err(to_rpc_error)
    }

    async fn get_manifest(&self, block_hash: BlockHash) -> RpcResult<Option<AsmManifest>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;

        self.manifest_db.get(&commitment).map_err(to_rpc_error)
    }
}

/// DB handles and the prover worker handle required to serve the proof and Moho-state
/// RPCs — populated only when proof generation is configured.
pub(crate) struct AsmProofRpcDeps {
    pub proof_db: SledProofDb,
    pub prover_handle: Arc<ProverWorkerHandle>,
    pub moho_state_db: SledMohoStateDb,
    pub export_entries_db: SledExportEntriesDb,
}

/// RPC handlers serving the ASM/Moho proofs and the prover worker's status.
pub(crate) struct AsmProofRpcServer {
    bitcoin_client: Arc<Client>,
    proof_db: SledProofDb,
    prover_handle: Arc<ProverWorkerHandle>,
}

impl AsmProofRpcServer {
    pub(crate) fn new(
        bitcoin_client: Arc<Client>,
        proof_db: SledProofDb,
        prover_handle: Arc<ProverWorkerHandle>,
    ) -> Self {
        Self {
            bitcoin_client,
            proof_db,
            prover_handle,
        }
    }
}

#[async_trait]
impl AsmProofApiServer for AsmProofRpcServer {
    async fn get_prover_status(&self) -> RpcResult<ProverStatus> {
        Ok(self.prover_handle.status())
    }

    async fn get_asm_proof(&self, block_hash: BlockHash) -> RpcResult<Option<AsmProof>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;
        let range = L1Range::single(commitment);

        self.proof_db
            .get_asm_proof(range)
            .await
            .map_err(to_rpc_error)
    }

    async fn get_moho_proof(&self, block_hash: BlockHash) -> RpcResult<Option<MohoProof>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;

        self.proof_db
            .get_moho_proof(commitment)
            .await
            .map_err(to_rpc_error)
    }
}

/// RPC handlers serving the per-block Moho state and export-entry MMR proofs.
pub(crate) struct AsmMohoRpcServer {
    bitcoin_client: Arc<Client>,
    moho_state_db: SledMohoStateDb,
    export_entries_db: SledExportEntriesDb,
}

impl AsmMohoRpcServer {
    pub(crate) fn new(
        bitcoin_client: Arc<Client>,
        moho_state_db: SledMohoStateDb,
        export_entries_db: SledExportEntriesDb,
    ) -> Self {
        Self {
            bitcoin_client,
            moho_state_db,
            export_entries_db,
        }
    }
}

#[async_trait]
impl AsmMohoApiServer for AsmMohoRpcServer {
    async fn get_moho_state(&self, block_hash: BlockHash) -> RpcResult<Option<MohoState>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;

        self.moho_state_db.get(commitment).map_err(to_rpc_error)
    }

    async fn get_export_entry_mmr_proof(
        &self,
        block_hash: BlockHash,
        container_id: u8,
        leaf: [u8; 32],
    ) -> RpcResult<Option<Vec<u8>>> {
        let commitment = to_block_commitment(&self.bitcoin_client, block_hash)
            .await
            .map_err(to_rpc_error)?;

        let proof = build_export_entry_mmr_proof(
            &self.moho_state_db,
            &self.export_entries_db,
            commitment,
            container_id,
            &leaf,
        )
        .await;

        match proof {
            Ok(proof) => Ok(Some(proof.as_ssz_bytes())),

            // The leaf simply isn't provable at this block. That is an ordinary
            // answer to the query, so it stays `null` on the wire.
            Err(
                ExportProofError::NoStateAtBlock(..)
                | ExportProofError::NoSuchContainer { .. }
                | ExportProofError::NoSuchLeaf { .. }
                | ExportProofError::LeafAfterBlock { .. },
            ) => Ok(None),

            // A store failure, or the two stores disagreeing. Neither is an
            // answer to the query, so both surface as errors.
            Err(
                e @ (ExportProofError::MohoState(..)
                | ExportProofError::ExportEntries(..)
                | ExportProofError::ProofDoesNotVerify { .. }),
            ) => Err(to_rpc_error(e)),
        }
    }
}

/// Run the RPC server.
#[expect(
    clippy::too_many_arguments,
    reason = "wires every dependency the RPC handlers need; one call site"
)]
pub(crate) async fn run_rpc_server(
    state_db: Arc<SledAsmStateDb>,
    manifest_db: Arc<SledAsmManifestDb>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
    params: AsmParams,
    proof_deps: Option<AsmProofRpcDeps>,
    rpc_host: String,
    rpc_port: u16,
    shutdown: ShutdownGuard,
) -> Result<()> {
    let asm_rpc = AsmRpcServer::new(
        state_db,
        manifest_db,
        asm_worker,
        bitcoin_client.clone(),
        params,
    );
    let mut module = AsmControlApiServer::into_rpc(asm_rpc.clone());
    module.merge(AsmStateApiServer::into_rpc(asm_rpc))?;

    if let Some(deps) = proof_deps {
        let AsmProofRpcDeps {
            proof_db,
            prover_handle,
            moho_state_db,
            export_entries_db,
        } = deps;

        let proof_module =
            AsmProofRpcServer::new(bitcoin_client.clone(), proof_db, prover_handle).into_rpc();
        module.merge(proof_module)?;

        let moho_module =
            AsmMohoRpcServer::new(bitcoin_client, moho_state_db, export_entries_db).into_rpc();
        module.merge(moho_module)?;
    }

    let server = ServerBuilder::default()
        .build(format!("{}:{}", rpc_host, rpc_port))
        .await?;

    let rpc_handle = server.start(module);
    let rpc_handle_for_shutdown = rpc_handle.clone();
    let rpc_handle_for_stop = rpc_handle.clone();

    info!(%rpc_host, %rpc_port, "ASM RPC server listening");

    tokio::select! {
        _ = shutdown.wait_for_shutdown() => {
            info!("ASM RPC server shutting down");
            if let Err(err) = rpc_handle.stop() {
                warn!(?err, "failed to stop ASM RPC server handle");
            }
            rpc_handle_for_shutdown.stopped().await;
        }
        _ = rpc_handle_for_stop.stopped() => {}
    }

    Ok(())
}
