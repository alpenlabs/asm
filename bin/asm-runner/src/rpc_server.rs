//! RPC server implementation for ASM queries

use std::{fmt::Display, sync::Arc};

use anyhow::Result;
use asm_storage::AsmStateDb;
use async_trait::async_trait;
use bitcoin::BlockHash;
use bitcoind_async_client::{Client, traits::Reader};
use jsonrpsee::{
    core::RpcResult,
    server::ServerBuilder,
    types::{ErrorObject, ErrorObjectOwned},
};
use ssz::Decode;
use strata_asm_proof_db::{ProofDb, SledProofDb};
use strata_asm_proof_types::{AsmProof, L1Range, MohoProof};
use strata_asm_proto_bridge_v1::{AssignmentEntry, BridgeV1State, DepositEntry};
use strata_asm_rpc::traits::AssignmentsApiServer;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_worker::{AsmWorkerHandle, AsmWorkerStatus};
use strata_btc_types::BlockHashExt;
use strata_identifiers::L1BlockCommitment;
use strata_tasks::ShutdownGuard;
use tracing::info;

/// Convert any error to an RPC error
fn to_rpc_error(e: impl Display) -> ErrorObjectOwned {
    ErrorObject::owned(-32000, e.to_string(), None::<()>)
}

/// ASM RPC server implementation
pub(crate) struct AsmRpcServer {
    state_db: Arc<AsmStateDb>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
    proof_db: Option<SledProofDb>,
}

impl AsmRpcServer {
    /// Create a new ASM RPC server
    pub(crate) fn new(
        state_db: Arc<AsmStateDb>,
        asm_worker: Arc<AsmWorkerHandle>,
        bitcoin_client: Arc<Client>,
        proof_db: Option<SledProofDb>,
    ) -> Self {
        Self {
            state_db,
            asm_worker,
            bitcoin_client,
            proof_db,
        }
    }
}

impl AsmRpcServer {
    async fn to_block_commitment(
        &self,
        block_hash: BlockHash,
    ) -> anyhow::Result<L1BlockCommitment> {
        let block_id = block_hash.to_l1_block_id();
        let height = self.bitcoin_client.get_block_height(&block_hash).await? as u32;
        Ok(L1BlockCommitment::new(height, block_id))
    }

    async fn get_bridge_state(&self, block_hash: BlockHash) -> RpcResult<Option<BridgeV1State>> {
        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;
        let state = self.state_db.get(&commitment).map_err(to_rpc_error)?;
        match state {
            Some(state) => {
                let bridge_state = state
                    .state()
                    .find_section(BRIDGE_V1_SUBPROTOCOL_ID)
                    .expect("bridge subprotocol should be enabled");

                let bridge_state = BridgeV1State::from_ssz_bytes(&bridge_state.data)
                    .expect("bridge state deserialization should be infallible");

                Ok(Some(bridge_state))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl AssignmentsApiServer for AsmRpcServer {
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

    async fn get_status(&self) -> RpcResult<AsmWorkerStatus> {
        Ok(self.asm_worker.monitor().get_current())
    }

    async fn get_asm_proof(&self, block_hash: BlockHash) -> RpcResult<Option<AsmProof>> {
        let Some(ref db) = self.proof_db else {
            return Ok(None);
        };

        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;
        let range = L1Range::single(commitment);

        db.get_asm_proof(range).await.map_err(to_rpc_error)
    }

    async fn get_moho_proof(&self, block_hash: BlockHash) -> RpcResult<Option<MohoProof>> {
        let Some(ref db) = self.proof_db else {
            return Ok(None);
        };

        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;

        db.get_moho_proof(commitment).await.map_err(to_rpc_error)
    }
}

/// Run the RPC server
pub(crate) async fn run_rpc_server(
    state_db: Arc<AsmStateDb>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
    proof_db: Option<SledProofDb>,
    rpc_host: String,
    rpc_port: u16,
    shutdown: ShutdownGuard,
) -> Result<()> {
    let rpc_server = AsmRpcServer::new(state_db, asm_worker, bitcoin_client, proof_db);

    let server = ServerBuilder::default()
        .build(format!("{}:{}", rpc_host, rpc_port))
        .await?;

    let rpc_handle = server.start(rpc_server.into_rpc());
    let rpc_handle_for_shutdown = rpc_handle.clone();
    let rpc_handle_for_stop = rpc_handle.clone();

    info!("ASM RPC server listening on {}:{}", rpc_host, rpc_port);

    tokio::select! {
        _ = shutdown.wait_for_shutdown() => {
            info!("ASM RPC server shutting down");
            let _ = rpc_handle.stop();
            rpc_handle_for_shutdown.stopped().await;
        }
        _ = rpc_handle_for_stop.stopped() => {}
    }

    Ok(())
}
