//! Peer proof source for follower mode.

use std::fmt::Debug;

use async_trait::async_trait;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_asm_prover_types::{AsmProof, L1Range, MohoProof, ProverStatus};
use strata_asm_rpc::traits::AsmProofApiClient;
use strata_btc_types::L1BlockIdBitcoinExt;
use strata_identifiers::L1BlockCommitment;

use crate::errors::{ProverError, ProverResult};

/// A peer asm-runner completed proofs can be fetched from.
///
/// Abstracts the peer's proof RPC surface (`AsmProofApi`) so the follower
/// logic can be unit-tested against a fake; [`RpcProofPeer`] is the real
/// implementation. Object-safe so the service state can hold it without
/// growing another type parameter. `Debug` is required so the state and
/// builder holding it can keep deriving `Debug`.
#[async_trait]
pub trait ProofPeer: Debug {
    /// Fetches the peer's prover status.
    async fn get_prover_status(&self) -> ProverResult<ProverStatus>;

    /// Fetches the completed ASM step proof for `range`, if the peer has it.
    async fn get_asm_proof(&self, range: &L1Range) -> ProverResult<Option<AsmProof>>;

    /// Fetches the completed Moho recursive proof for `block`, if the peer
    /// has it.
    async fn get_moho_proof(&self, block: &L1BlockCommitment) -> ProverResult<Option<MohoProof>>;
}

/// [`ProofPeer`] backed by a peer asm-runner's proof RPC over HTTP.
///
/// No retry wrapper: the follower probes the peer every tick and tolerates a
/// configured number of consecutive failures before falling back to local
/// proving, so the tick loop *is* the retry policy.
#[derive(Debug)]
pub struct RpcProofPeer {
    client: HttpClient,
}

impl RpcProofPeer {
    /// Builds a client for the peer asm-runner's RPC server at `peer_url`.
    pub fn new(peer_url: &str) -> ProverResult<Self> {
        let client = HttpClientBuilder::default()
            .build(peer_url)
            .map_err(|e| ProverError::peer("failed to build peer RPC client", e))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl ProofPeer for RpcProofPeer {
    async fn get_prover_status(&self) -> ProverResult<ProverStatus> {
        self.client
            .get_prover_status()
            .await
            .map_err(|e| ProverError::peer("failed to fetch peer prover status", e))
    }

    async fn get_asm_proof(&self, range: &L1Range) -> ProverResult<Option<AsmProof>> {
        // The peer keys proofs by block hash, which can only address
        // single-block ranges — the only kind the worker creates.
        if range.start() != range.end() {
            return Err(ProverError::PeerUnaddressable("multi-block ASM range"));
        }
        let block_hash = range.end().blkid().to_block_hash();
        self.client
            .get_asm_proof(block_hash)
            .await
            .map_err(|e| ProverError::peer("failed to fetch ASM proof from peer", e))
    }

    async fn get_moho_proof(&self, block: &L1BlockCommitment) -> ProverResult<Option<MohoProof>> {
        let block_hash = block.blkid().to_block_hash();
        self.client
            .get_moho_proof(block_hash)
            .await
            .map_err(|e| ProverError::peer("failed to fetch Moho proof from peer", e))
    }
}
