//! RPC server implementation for ASM queries

use std::{fmt::Display, sync::Arc};

use anyhow::Result;
use asm_storage::{AsmStateDb, ExportEntriesDb};
use async_trait::async_trait;
use bitcoin::BlockHash;
use bitcoind_async_client::{Client, traits::Reader};
use jsonrpsee::{
    core::RpcResult,
    server::ServerBuilder,
    types::{ErrorObject, ErrorObjectOwned},
};
use ssz::{Decode, Encode};
use strata_asm_proof_db::{ProofDb, SledMohoStateDb, SledProofDb};
use strata_asm_proof_types::{AsmProof, L1Range, MohoProof};
use strata_asm_proto_bridge_v1::{AssignmentEntry, BridgeV1State, DepositEntry};
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_proto_checkpoint::state::CheckpointState;
use strata_asm_proto_checkpoint_txs::CHECKPOINT_SUBPROTOCOL_ID;
use strata_asm_proto_checkpoint_types::CheckpointTip;
use strata_asm_rpc::traits::AssignmentsApiServer;
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
    moho_state_db: Option<SledMohoStateDb>,
    export_entries_db: Option<ExportEntriesDb>,
}

impl AsmRpcServer {
    /// Create a new ASM RPC server
    pub(crate) fn new(
        state_db: Arc<AsmStateDb>,
        asm_worker: Arc<AsmWorkerHandle>,
        bitcoin_client: Arc<Client>,
        proof_db: Option<SledProofDb>,
        moho_state_db: Option<SledMohoStateDb>,
        export_entries_db: Option<ExportEntriesDb>,
    ) -> Self {
        Self {
            state_db,
            asm_worker,
            bitcoin_client,
            proof_db,
            moho_state_db,
            export_entries_db,
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

    async fn get_checkpoint_state(
        &self,
        block_hash: BlockHash,
    ) -> RpcResult<Option<CheckpointState>> {
        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;
        let state = self.state_db.get(&commitment).map_err(to_rpc_error)?;
        match state {
            Some(state) => {
                let checkpoint_state = state
                    .state()
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

    async fn get_checkpoint_tip(&self, block_hash: BlockHash) -> RpcResult<Option<CheckpointTip>> {
        match self.get_checkpoint_state(block_hash).await? {
            Some(checkpoint_state) => Ok(Some(*checkpoint_state.verified_tip())),
            None => Ok(None),
        }
    }

    async fn get_export_entry_mmr_proof(
        &self,
        block_hash: BlockHash,
        container_id: u8,
        leaf: Vec<u8>,
    ) -> RpcResult<Option<Vec<u8>>> {
        let Some(ref moho_state_db) = self.moho_state_db else {
            return Ok(None);
        };
        let Some(ref export_entries_db) = self.export_entries_db else {
            return Ok(None);
        };

        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;

        build_export_entry_mmr_proof(
            moho_state_db,
            export_entries_db,
            commitment,
            container_id,
            &leaf,
        )
        .map_err(to_rpc_error)
    }

    async fn get_moho_state(&self, block_hash: BlockHash) -> RpcResult<Option<Vec<u8>>> {
        let Some(ref moho_state_db) = self.moho_state_db else {
            return Ok(None);
        };

        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;

        let Some(state) = moho_state_db.get(commitment).map_err(to_rpc_error)? else {
            return Ok(None);
        };

        Ok(Some(state.as_ssz_bytes()))
    }
}

#[derive(Debug, thiserror::Error)]
enum MmrProofError {
    #[error("leaf must be 32 bytes, got {0}")]
    InvalidLeafLength(usize),
    #[error(transparent)]
    Sled(#[from] sled::Error),
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

/// SSZ-encoded MMR inclusion proof for `leaf` in `container_id` at `commitment`.
///
/// `Ok(None)` if the leaf or container isn't in this snapshot yet. `Err` only
/// for bad input or storage failures.
fn build_export_entry_mmr_proof(
    moho_state_db: &SledMohoStateDb,
    export_entries_db: &ExportEntriesDb,
    commitment: L1BlockCommitment,
    container_id: u8,
    leaf: &[u8],
) -> Result<Option<Vec<u8>>, MmrProofError> {
    let leaf_hash: [u8; 32] = leaf
        .try_into()
        .map_err(|_| MmrProofError::InvalidLeafLength(leaf.len()))?;

    let Some(moho_state) = moho_state_db.get(commitment)? else {
        return Ok(None);
    };

    let Some(container) = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == container_id)
    else {
        return Ok(None);
    };

    let at_leaf_count = container.entries_mmr().num_entries();

    let Some((mmr_index, _height)) = export_entries_db.find_index(container_id, &leaf_hash)? else {
        return Ok(None);
    };

    // Guard against entries appended after `commitment`: the index is populated
    // monotonically by the worker, but the historical `MohoState` only saw the
    // first `at_leaf_count` of them.
    if mmr_index >= at_leaf_count {
        return Ok(None);
    }

    let proof = export_entries_db.generate_proof(container_id, mmr_index, at_leaf_count)?;
    Ok(Some(proof.as_ssz_bytes()))
}

/// Run the RPC server
#[expect(
    clippy::too_many_arguments,
    reason = "bootstrap-only plumbing; grouping into a struct adds noise without benefit"
)]
pub(crate) async fn run_rpc_server(
    state_db: Arc<AsmStateDb>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
    proof_db: Option<SledProofDb>,
    moho_state_db: Option<SledMohoStateDb>,
    export_entries_db: Option<ExportEntriesDb>,
    rpc_host: String,
    rpc_port: u16,
    shutdown: ShutdownGuard,
) -> Result<()> {
    let rpc_server = AsmRpcServer::new(
        state_db,
        asm_worker,
        bitcoin_client,
        proof_db,
        moho_state_db,
        export_entries_db,
    );

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

#[cfg(test)]
mod tests {
    //! Tests for [`build_export_entry_mmr_proof`] against real sled storage.
    //! Mirrors the worker's invariant: each `NewExportEntry` hits both `ExportState` and
    //! `ExportEntriesDb` in order.
    use moho_types::{ExportState, InnerStateCommitment, MohoState};
    use ssz::Decode;
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use strata_merkle::MerkleProofB32;
    use strata_predicate::PredicateKey;

    use super::*;

    /// Container ID for the Bridge V1 subprotocol; matches `BRIDGE_V1_CONTAINER_ID` in functional
    /// tests.
    const BRIDGE_V1_CONTAINER_ID: u8 = 2;

    fn temp_dbs() -> (
        sled::Db,
        SledMohoStateDb,
        ExportEntriesDb,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let sled_db = sled::open(dir.path()).unwrap();
        let moho_state_db = SledMohoStateDb::open(&sled_db).unwrap();
        let export_entries_db = ExportEntriesDb::open(&sled_db).unwrap();
        (sled_db, moho_state_db, export_entries_db, dir)
    }

    fn commitment(height: u32, seed: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::from([seed; 32])))
    }

    fn entry_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Same dual-write the worker does per block: each entry hits both the
    /// `ExportState` MMR and the `ExportEntriesDb` leaf log.
    fn apply_block(
        moho: &SledMohoStateDb,
        idx: &ExportEntriesDb,
        prev: MohoState,
        at: L1BlockCommitment,
        entries: &[(u8, [u8; 32])],
    ) -> MohoState {
        let mut export = prev.export_state().clone();
        for (container_id, hash) in entries {
            export.add_entry(*container_id, *hash).unwrap();
            idx.append(*container_id, at.height(), *hash).unwrap();
        }
        let next = MohoState::new(
            InnerStateCommitment::from([0u8; 32]),
            PredicateKey::always_accept(),
            export,
        );
        moho.store(at, next.clone()).unwrap();
        next
    }

    fn genesis_moho() -> MohoState {
        MohoState::new(
            InnerStateCommitment::from([0u8; 32]),
            PredicateKey::always_accept(),
            ExportState::new(vec![]).unwrap(),
        )
    }

    #[test]
    fn returns_proof_that_verifies_against_historical_mmr() {
        let (_db, moho, idx, _tmp) = temp_dbs();

        // Two blocks each add two entries to container BRIDGE_V1_CONTAINER_ID. Total 4 entries.
        let b1 = commitment(100, 1);
        let state_at_b1 = apply_block(
            &moho,
            &idx,
            genesis_moho(),
            b1,
            &[
                (BRIDGE_V1_CONTAINER_ID, entry_hash(0xa0)),
                (BRIDGE_V1_CONTAINER_ID, entry_hash(0xa1)),
            ],
        );
        let b2 = commitment(101, 2);
        let state_at_b2 = apply_block(
            &moho,
            &idx,
            state_at_b1,
            b2,
            &[
                (BRIDGE_V1_CONTAINER_ID, entry_hash(0xa2)),
                (BRIDGE_V1_CONTAINER_ID, entry_hash(0xa3)),
            ],
        );

        let leaf = entry_hash(0xa2);
        let bytes = build_export_entry_mmr_proof(&moho, &idx, b2, BRIDGE_V1_CONTAINER_ID, &leaf)
            .unwrap()
            .expect("proof should be present");

        // SSZ-decode and verify against the container's compact MMR at b2.
        let proof = MerkleProofB32::from_ssz_bytes(&bytes).unwrap();
        let container = state_at_b2
            .export_state()
            .containers()
            .iter()
            .find(|c| c.container_id() == BRIDGE_V1_CONTAINER_ID)
            .unwrap();
        assert_eq!(container.entries_mmr().num_entries(), 4);
        assert!(
            container.entries_mmr().verify(&proof, &leaf),
            "proof must verify against MohoState's compact MMR at the queried block"
        );
    }

    #[test]
    fn proof_at_earlier_block_uses_that_blocks_mmr_size() {
        let (_db, moho, idx, _tmp) = temp_dbs();

        // b1 has one entry for BRIDGE_V1_CONTAINER_ID.
        let b1 = commitment(100, 1);
        let state_at_b1 = apply_block(
            &moho,
            &idx,
            genesis_moho(),
            b1,
            &[(BRIDGE_V1_CONTAINER_ID, entry_hash(0xa0))],
        );
        // b2 adds two more.
        let b2 = commitment(101, 2);
        apply_block(
            &moho,
            &idx,
            state_at_b1.clone(),
            b2,
            &[
                (BRIDGE_V1_CONTAINER_ID, entry_hash(0xa1)),
                (BRIDGE_V1_CONTAINER_ID, entry_hash(0xa2)),
            ],
        );

        // Querying with leaf 0xa0 at block b1 must produce a proof valid
        // against the size-1 MMR, not the size-3 MMR at b2.
        let leaf = entry_hash(0xa0);
        let bytes = build_export_entry_mmr_proof(&moho, &idx, b1, BRIDGE_V1_CONTAINER_ID, &leaf)
            .unwrap()
            .unwrap();
        let proof = MerkleProofB32::from_ssz_bytes(&bytes).unwrap();
        let container_at_b1 = state_at_b1
            .export_state()
            .containers()
            .iter()
            .find(|c| c.container_id() == BRIDGE_V1_CONTAINER_ID)
            .unwrap();
        assert_eq!(container_at_b1.entries_mmr().num_entries(), 1);
        assert!(container_at_b1.entries_mmr().verify(&proof, &leaf));
    }

    #[test]
    fn none_when_leaf_inserted_after_queried_block() {
        let (_db, moho, idx, _tmp) = temp_dbs();

        // Only one entry exists at b1.
        let b1 = commitment(100, 1);
        let state_at_b1 = apply_block(
            &moho,
            &idx,
            genesis_moho(),
            b1,
            &[(BRIDGE_V1_CONTAINER_ID, entry_hash(0xa0))],
        );
        // A later entry at b2.
        let b2 = commitment(101, 2);
        apply_block(
            &moho,
            &idx,
            state_at_b1,
            b2,
            &[(BRIDGE_V1_CONTAINER_ID, entry_hash(0xa1))],
        );

        // Querying 0xa1 at b1 must return None — it was inserted later.
        let out = build_export_entry_mmr_proof(
            &moho,
            &idx,
            b1,
            BRIDGE_V1_CONTAINER_ID,
            &entry_hash(0xa1),
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn none_when_leaf_unknown() {
        let (_db, moho, idx, _tmp) = temp_dbs();
        let b1 = commitment(100, 1);
        apply_block(
            &moho,
            &idx,
            genesis_moho(),
            b1,
            &[(BRIDGE_V1_CONTAINER_ID, entry_hash(0xa0))],
        );

        let out = build_export_entry_mmr_proof(
            &moho,
            &idx,
            b1,
            BRIDGE_V1_CONTAINER_ID,
            &entry_hash(0xff),
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn none_when_container_missing() {
        let (_db, moho, idx, _tmp) = temp_dbs();
        let b1 = commitment(100, 1);
        apply_block(
            &moho,
            &idx,
            genesis_moho(),
            b1,
            &[(BRIDGE_V1_CONTAINER_ID, entry_hash(0xa0))],
        );

        // Query a container_id that was never populated. Indistinguishable from
        // a container that hasn't been created yet — both are legitimate absence.
        let out = build_export_entry_mmr_proof(&moho, &idx, b1, 99, &entry_hash(0xa0)).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn none_when_state_missing() {
        let (_db, moho, idx, _tmp) = temp_dbs();
        // No state stored for this commitment.
        let out = build_export_entry_mmr_proof(
            &moho,
            &idx,
            commitment(999, 9),
            BRIDGE_V1_CONTAINER_ID,
            &entry_hash(0xa0),
        )
        .unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn err_on_wrong_sized_leaf() {
        let (_db, moho, idx, _tmp) = temp_dbs();
        let b1 = commitment(100, 1);
        apply_block(
            &moho,
            &idx,
            genesis_moho(),
            b1,
            &[(BRIDGE_V1_CONTAINER_ID, entry_hash(0xa0))],
        );

        let err =
            build_export_entry_mmr_proof(&moho, &idx, b1, BRIDGE_V1_CONTAINER_ID, &[0xa0; 31])
                .unwrap_err();
        assert!(matches!(err, MmrProofError::InvalidLeafLength(31)));
        let err =
            build_export_entry_mmr_proof(&moho, &idx, b1, BRIDGE_V1_CONTAINER_ID, &[0xa0; 33])
                .unwrap_err();
        assert!(matches!(err, MmrProofError::InvalidLeafLength(33)));
    }

    #[test]
    fn moho_state_round_trips_via_ssz() {
        let (_db, moho, _idx, _tmp) = temp_dbs();
        let at = commitment(100, 1);
        let state = genesis_moho();
        moho.store(at, state.clone()).unwrap();

        let bytes = moho.get(at).unwrap().unwrap().as_ssz_bytes();
        let decoded = MohoState::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn moho_state_missing_returns_none() {
        let (_db, moho, _idx, _tmp) = temp_dbs();
        assert!(moho.get(commitment(999, 9)).unwrap().is_none());
    }
}
