//! Standalone verification of export entry inclusion in a Moho state.
//!
//! Verifies that an entry hash is included in a bridge export container's MMR
//! within a `MohoState`, and that the state matches a known commitment.

use moho_types::{MohoState, MohoStateCommitment};
use strata_merkle::{MerkleProofB32, Mmr, Sha256Hasher};

/// Bridge V1 export container ID.
pub const BRIDGE_V1_CONTAINER_ID: u8 = 2;

/// Verify that `entry_hash` is included in the bridge export container's MMR
/// within the given `MohoState`, and that the state matches `expected_commitment`.
///
/// Panics if any check fails.
pub fn verify_export_entry(
    moho_state: &MohoState,
    expected_commitment: &MohoStateCommitment,
    mmr_proof: &MerkleProofB32,
    entry_hash: &[u8; 32],
) {
    let computed = moho_state.compute_commitment();
    assert_eq!(
        computed.inner(),
        expected_commitment.inner(),
        "moho state commitment mismatch"
    );

    let container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_V1_CONTAINER_ID)
        .expect("bridge container not found in export state");

    assert!(
        Mmr::<Sha256Hasher>::verify(container.entries_mmr(), mmr_proof, entry_hash),
        "MMR inclusion proof verification failed"
    );
}
