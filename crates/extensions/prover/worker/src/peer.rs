//! Peer proof source for follower mode.

use std::fmt::Debug;

use async_trait::async_trait;
use strata_asm_prover_types::{AsmProof, L1Range, MohoProof, ProverStatus};
use strata_identifiers::L1BlockCommitment;

use crate::errors::ProverResult;

/// A peer asm-runner completed proofs can be fetched from.
///
/// Abstracts the peer's proof RPC surface (`AsmProofApi`) so the follower
/// logic stays transport-agnostic and unit-testable; the binary supplies the
/// RPC-client implementation. Object-safe so the service state can hold it
/// without growing another type parameter. `Debug` is required so the state
/// and builder holding it can keep deriving `Debug`.
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
