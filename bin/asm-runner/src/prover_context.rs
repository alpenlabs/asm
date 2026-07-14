//! Concrete [`ProverContext`] implementation for the ASM runner.
//!
//! [`AsmProverContext`] is the prover-side analogue of
//! [`AsmWorkerContext`](crate::worker_context::AsmWorkerContext): it wires the
//! sled-backed proof store, the Moho-state store, the ASM anchor-state store,
//! and the Bitcoin client into the concern traits the prover worker drives
//! against. The proof-store traits are delegated to [`SledProofDb`]; Moho-state
//! reads to [`SledMohoStateDb`]; anchor reads to [`SledAsmStateDb`]; aux reads to
//! [`SledAsmAuxDataDb`]; and L1 block reads to the Bitcoin [`Client`].
//!
//! [`ProverContext`]: strata_asm_prover_worker::ProverContext

use std::sync::Arc;

use asm_storage::{SledAsmAuxDataDb, SledAsmStateDb};
use bitcoin::{Block, block::Header};
use bitcoind_async_client::{Client, traits::Reader};
use moho_types::MohoState;
use strata_asm_common::{AnchorState, AuxData};
use strata_asm_moho_storage::{MohoStateDb, SledMohoStateDb};
use strata_asm_prover_storage::{
    ProofDb, RemoteProofMappingDb, RemoteProofMappingError, RemoteProofStatusDb,
    RemoteProofStatusError, SledProofDb,
};
use strata_asm_prover_types::{AsmProof, L1Range, MohoProof, ProofId, RemoteProofId};
use strata_asm_prover_worker::{
    AnchorStateReader, AuxDataReader, L1BlockProvider, ProverError, ProverResult,
};
use strata_btc_types::{BlockHashExt, L1BlockIdBitcoinExt};
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use zkaleido::RemoteProofStatus;

/// Concrete prover context for the ASM runner.
///
/// Implements every concern trait the prover worker needs, so it satisfies the
/// `ProverContext` umbrella via its blanket impl. The bitcoin reads are async
/// and hit the client directly — the orchestrator drives this from a
/// single-threaded runtime, so blocking on the client would deadlock.
pub(crate) struct AsmProverContext {
    proof_db: SledProofDb,
    moho_state_db: SledMohoStateDb,
    state_db: Arc<SledAsmStateDb>,
    aux_db: Arc<SledAsmAuxDataDb>,
    bitcoin_client: Arc<Client>,
}

impl AsmProverContext {
    pub(crate) fn new(
        proof_db: SledProofDb,
        moho_state_db: SledMohoStateDb,
        state_db: Arc<SledAsmStateDb>,
        aux_db: Arc<SledAsmAuxDataDb>,
        bitcoin_client: Arc<Client>,
    ) -> Self {
        Self {
            proof_db,
            moho_state_db,
            state_db,
            aux_db,
            bitcoin_client,
        }
    }
}

// ---- Proof persistence: delegate to the sled proof store ------------------

impl ProofDb for AsmProverContext {
    type Error = sled::Error;

    async fn store_asm_proof(&self, range: L1Range, proof: AsmProof) -> Result<(), Self::Error> {
        self.proof_db.store_asm_proof(range, proof).await
    }

    async fn get_asm_proof(&self, range: L1Range) -> Result<Option<AsmProof>, Self::Error> {
        self.proof_db.get_asm_proof(range).await
    }

    async fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> Result<(), Self::Error> {
        self.proof_db.store_moho_proof(l1ref, proof).await
    }

    async fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoProof>, Self::Error> {
        self.proof_db.get_moho_proof(l1ref).await
    }

    async fn get_latest_moho_proof(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error> {
        self.proof_db.get_latest_moho_proof().await
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        self.proof_db.prune(before_height).await
    }
}

impl RemoteProofMappingDb for AsmProverContext {
    type Error = RemoteProofMappingError;

    async fn get_remote_proof_id(&self, id: ProofId) -> Result<Option<RemoteProofId>, Self::Error> {
        self.proof_db.get_remote_proof_id(id).await
    }

    async fn get_proof_id(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<ProofId>, Self::Error> {
        self.proof_db.get_proof_id(remote_id).await
    }

    async fn put_remote_proof_id(
        &self,
        id: ProofId,
        remote_id: RemoteProofId,
    ) -> Result<(), Self::Error> {
        self.proof_db.put_remote_proof_id(id, remote_id).await
    }
}

impl RemoteProofStatusDb for AsmProverContext {
    type Error = RemoteProofStatusError;

    async fn put_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        self.proof_db.put_status(remote_id, status).await
    }

    async fn update_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        self.proof_db.update_status(remote_id, status).await
    }

    async fn get_status(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<RemoteProofStatus>, Self::Error> {
        self.proof_db.get_status(remote_id).await
    }

    async fn get_all_in_progress(
        &self,
    ) -> Result<Vec<(RemoteProofId, RemoteProofStatus)>, Self::Error> {
        self.proof_db.get_all_in_progress().await
    }

    async fn remove(&self, remote_id: &RemoteProofId) -> Result<(), Self::Error> {
        self.proof_db.remove(remote_id).await
    }
}

// ---- Moho-state reads: delegate to the sled moho-state store --------------

impl MohoStateDb for AsmProverContext {
    type Error = sled::Error;

    async fn store_moho_state(
        &self,
        l1ref: L1BlockCommitment,
        state: MohoState,
    ) -> Result<(), Self::Error> {
        self.moho_state_db.store_moho_state(l1ref, state).await
    }

    async fn get_moho_state(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoState>, Self::Error> {
        self.moho_state_db.get_moho_state(l1ref).await
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        self.moho_state_db.prune(before_height).await
    }
}

// ---- Chain/state reads for the input builder ------------------------------

impl AnchorStateReader for AsmProverContext {
    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> ProverResult<AnchorState> {
        // `SledAsmStateDb` returns `anyhow::Result`; carry the cause chain by
        // boxing it into the `Storage` variant's source rather than re-stringifying.
        self.state_db
            .get(blockid)
            .map_err(|e| ProverError::Storage {
                context: "failed to read anchor state",
                source: e.into(),
            })?
            .ok_or(ProverError::NotFound("anchor state not found"))
    }

    fn get_latest_anchor_state(&self) -> ProverResult<Option<AnchorState>> {
        self.state_db
            .get_latest()
            .map_err(|e| ProverError::Storage {
                context: "failed to read latest anchor state",
                source: e.into(),
            })
    }

    fn contains_anchor_state(&self, blockid: &L1BlockCommitment) -> ProverResult<bool> {
        self.state_db
            .contains(blockid)
            .map_err(|e| ProverError::Storage {
                context: "failed to check anchor state presence",
                source: e.into(),
            })
    }
}

impl AuxDataReader for AsmProverContext {
    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> ProverResult<AuxData> {
        self.aux_db
            .get(blockid)
            .map_err(|e| ProverError::Storage {
                context: "failed to read aux data",
                source: e.into(),
            })?
            .ok_or(ProverError::NotFound("aux data not found for block"))
    }
}

impl L1BlockProvider for AsmProverContext {
    async fn get_l1_block(&self, blockid: &L1BlockId) -> ProverResult<Block> {
        let hash = blockid.to_block_hash();
        self.bitcoin_client
            .get_block(&hash)
            .await
            .map_err(|e| ProverError::storage("failed to fetch Bitcoin block", e))
    }

    async fn get_l1_block_header(&self, blockid: &L1BlockId) -> ProverResult<Header> {
        let hash = blockid.to_block_hash();
        self.bitcoin_client
            .get_block_header(&hash)
            .await
            .map_err(|e| ProverError::storage("failed to fetch Bitcoin block header", e))
    }

    async fn get_l1_block_count(&self) -> ProverResult<u64> {
        self.bitcoin_client
            .get_block_count()
            .await
            .map_err(|e| ProverError::storage("failed to fetch L1 block count", e))
    }

    async fn get_l1_block_hash(&self, height: u64) -> ProverResult<L1BlockId> {
        let hash = self
            .bitcoin_client
            .get_block_hash(height)
            .await
            .map_err(|e| ProverError::storage("failed to fetch L1 block hash", e))?;
        Ok(hash.to_l1_block_id())
    }
}
