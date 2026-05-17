//! Traits for the AnchorStateMachine (ASM) RPC service.

use bitcoin::BlockHash;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_asm_proof_types::{AsmProof, MohoProof};
use strata_asm_proto_bridge_v1::{AssignmentEntry, DepositEntry};
use strata_asm_proto_checkpoint_types::CheckpointTip;
use strata_asm_worker::{AsmState, AsmWorkerStatus};

/// Control-plane ASM RPCs: liveness and overall worker status.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "strata_asm"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "strata_asm"))]
pub trait AsmControlApi {
    /// Return the uptime of the ASM runner in seconds, measured against a monotonic clock
    /// captured when the RPC server was constructed. Doubles as a liveness probe: any successful
    /// response means the RPC server is reachable.
    #[method(name = "uptime")]
    async fn get_uptime(&self) -> RpcResult<u64>;

    /// Return the current ASM worker status.
    #[method(name = "getStatus")]
    async fn get_status(&self) -> RpcResult<AsmWorkerStatus>;
}

/// State-query ASM RPCs: derived purely from the ASM state DB and keyed by L1 block hash.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "strata_asm"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "strata_asm"))]
pub trait AsmStateApi {
    /// Return the assignment state for the provided Bitcoin block hash.
    #[method(name = "getAssignments")]
    async fn get_assignments(&self, block_hash: BlockHash) -> RpcResult<Vec<AssignmentEntry>>;

    /// Return the deposit state for the provided Bitcoin block hash.
    #[method(name = "getDeposits")]
    async fn get_deposits(&self, block_hash: BlockHash) -> RpcResult<Vec<DepositEntry>>;

    /// Return the verified checkpoint tip for the provided Bitcoin block hash.
    #[method(name = "getCheckpointTip")]
    async fn get_checkpoint_tip(&self, block_hash: BlockHash) -> RpcResult<Option<CheckpointTip>>;

    /// Return the `AsmState` for the provided Bitcoin block hash.
    #[method(name = "getAsmState")]
    async fn get_asm_state(&self, block_hash: BlockHash) -> RpcResult<Option<AsmState>>;
}

/// Proof-related ASM RPCs: registered only when the proof orchestrator is configured.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "strata_asm"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "strata_asm"))]
pub trait AsmProofApi {
    /// Return the ASM step proof for the given block, if one exists.
    #[method(name = "getAsmProof")]
    async fn get_asm_proof(&self, block_hash: BlockHash) -> RpcResult<Option<AsmProof>>;

    /// Return the Moho recursive proof for the given block, if one exists.
    #[method(name = "getMohoProof")]
    async fn get_moho_proof(&self, block_hash: BlockHash) -> RpcResult<Option<MohoProof>>;

    /// Return the SSZ-encoded `MohoState` for the provided Bitcoin block hash.
    #[method(name = "getMohoState")]
    async fn get_moho_state(&self, block_hash: BlockHash) -> RpcResult<Option<Vec<u8>>>;

    /// Return the MMR inclusion proof for `leaf` in the export container at `container_id`.
    #[method(name = "getExportEntryMMRProof")]
    async fn get_export_entry_mmr_proof(
        &self,
        block_hash: BlockHash,
        container_id: u8,
        leaf: Vec<u8>,
    ) -> RpcResult<Option<Vec<u8>>>;
}
