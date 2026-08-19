//! Inclusion proofs for export entries, built from the two Moho stores.
//!
//! [`MohoState`](moho_types::MohoState) keeps only each container's compact MMR,
//! so a proof needs both stores: the state store fixes the MMR size at the
//! queried block, and the entry index supplies the leaf position and the
//! sibling hashes.

use std::fmt::Debug;

use strata_identifiers::L1BlockCommitment;
use strata_merkle::MerkleProofB32;

use crate::{ExportEntriesDb, MohoStateDb};

/// Why an export-entry inclusion proof could not be built.
///
/// The absence variants each name a distinct reason the requested leaf is not
/// provable at the queried block. They are ordinary outcomes of a query, not
/// faults: callers that treat "no such leaf" as an empty response should match
/// on them rather than on a bare `None`.
///
/// The store variants carry the originating error. The traits only require
/// [`Debug`] of them, so that is what is rendered.
#[derive(Debug, thiserror::Error)]
pub enum ExportProofError<M: Debug, E: Debug> {
    /// No Moho state is stored for the queried block.
    #[error("no moho state at {0:?}")]
    NoStateAtBlock(L1BlockCommitment),

    /// The block's state has no container with this id.
    #[error("no container {container_id} at {commitment:?}")]
    NoSuchContainer {
        /// The container that was queried.
        container_id: u8,
        /// The block the state was read at.
        commitment: L1BlockCommitment,
    },

    /// The leaf is not in the container's entry index at all.
    #[error("leaf not found in container {container_id}")]
    NoSuchLeaf {
        /// The container that was queried.
        container_id: u8,
    },

    /// The leaf exists, but was appended after the queried block, so it is not
    /// covered by that block's MMR.
    ///
    /// The index grows monotonically as the worker advances, while the
    /// historical state only ever saw the first `at_leaf_count` leaves.
    #[error(
        "leaf is at index {mmr_index} but container {container_id} held only \
         {at_leaf_count} entries at the queried block"
    )]
    LeafAfterBlock {
        /// The container that was queried.
        container_id: u8,
        /// Where the leaf sits in the index today.
        mmr_index: u64,
        /// How many leaves the container held at the queried block.
        at_leaf_count: u64,
    },

    /// The generated proof did not verify against the block's MMR.
    ///
    /// The two stores disagree: the entry index produced a proof that the
    /// state's compact MMR rejects. Neither input is attacker-controlled, so
    /// this means the mirrored leaves have drifted from the state they are
    /// supposed to track.
    #[error(
        "proof for index {mmr_index} in container {container_id} does not verify \
         against the mmr at {commitment:?}"
    )]
    ProofDoesNotVerify {
        /// The container that was queried.
        container_id: u8,
        /// The leaf's index in the container.
        mmr_index: u64,
        /// The block whose MMR rejected the proof.
        commitment: L1BlockCommitment,
    },

    /// The Moho state store failed.
    #[error("moho state store: {0:?}")]
    MohoState(M),

    /// The export-entry index failed.
    #[error("export entry index: {0:?}")]
    ExportEntries(E),
}

/// Builds an MMR inclusion proof for `leaf` in `container_id`, as of
/// `commitment`.
///
/// The proof verifies against the container's compact MMR in the [`MohoState`]
/// stored at `commitment`, which fixes the MMR size. Encoding is left to the
/// caller.
///
/// The proof is checked against that MMR before it is returned, so a caller
/// never hands out a proof that would fail at the verifier.
///
/// [`MohoState`]: moho_types::MohoState
pub async fn build_export_entry_mmr_proof<M, E>(
    moho_state_db: &M,
    export_entries_db: &E,
    commitment: L1BlockCommitment,
    container_id: u8,
    leaf: &[u8; 32],
) -> Result<MerkleProofB32, ExportProofError<M::Error, E::Error>>
where
    M: MohoStateDb,
    E: ExportEntriesDb,
{
    let moho_state = moho_state_db
        .get_moho_state(commitment)
        .await
        .map_err(ExportProofError::MohoState)?
        .ok_or(ExportProofError::NoStateAtBlock(commitment))?;

    let container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == container_id)
        .ok_or(ExportProofError::NoSuchContainer {
            container_id,
            commitment,
        })?;

    let at_leaf_count = container.entries_mmr().num_entries();

    let mmr_index = export_entries_db
        .find_entry_index(container_id, *leaf)
        .await
        .map_err(ExportProofError::ExportEntries)?
        .ok_or(ExportProofError::NoSuchLeaf { container_id })?;

    if mmr_index >= at_leaf_count {
        return Err(ExportProofError::LeafAfterBlock {
            container_id,
            mmr_index,
            at_leaf_count,
        });
    }

    let proof = export_entries_db
        .generate_entry_proof(container_id, mmr_index, at_leaf_count)
        .await
        .map_err(ExportProofError::ExportEntries)?;

    // The proof comes from the mirrored leaves, but it is consumed against the
    // state's compact MMR. Check it here so drift between the two stores fails
    // at the source rather than at whoever verifies it later.
    if !container.entries_mmr().verify(&proof, leaf) {
        return Err(ExportProofError::ProofDoesNotVerify {
            container_id,
            mmr_index,
            commitment,
        });
    }

    Ok(proof)
}

#[cfg(test)]
mod tests {
    //! Tests against real sled storage, mirroring the worker's invariant: each
    //! new export entry hits both `ExportState` and the entry index, in order.
    use moho_types::{ExportState, InnerStateCommitment, MohoState};
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_predicate::PredicateKey;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::{SledExportEntriesDb, SledMohoStateDb};

    /// Stands in for a real subprotocol's container. Any `u8` works here; the
    /// proof code treats it as an opaque namespace.
    const CONTAINER_ID: u8 = 2;

    fn temp_dbs() -> (SledMohoStateDb, SledExportEntriesDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let sled_db = sled::open(dir.path()).unwrap();
        let moho_state_db = SledMohoStateDb::open(&sled_db).unwrap();
        let export_entries_db = SledExportEntriesDb::open(&sled_db).unwrap();
        (moho_state_db, export_entries_db, dir)
    }

    fn commitment(height: u32, seed: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::from([seed; 32])))
    }

    fn entry_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn genesis_moho() -> MohoState {
        MohoState::new(
            InnerStateCommitment::from([0u8; 32]),
            PredicateKey::always_accept(),
            ExportState::new(vec![]).unwrap(),
        )
    }

    /// Same dual-write the worker does per block: each entry hits both the
    /// `ExportState` MMR and the export-entry index.
    async fn apply_block(
        moho: &SledMohoStateDb,
        idx: &SledExportEntriesDb,
        prev: MohoState,
        at: L1BlockCommitment,
        entries: &[(u8, [u8; 32])],
    ) -> MohoState {
        let mut export = prev.export_state().clone();
        for (container_id, hash) in entries {
            export.add_entry(*container_id, *hash).unwrap();
            idx.append_entries(*container_id, at.height(), vec![*hash])
                .await
                .unwrap();
        }
        let next = MohoState::new(
            InnerStateCommitment::from([0u8; 32]),
            PredicateKey::always_accept(),
            export,
        );
        moho.store_moho_state(at, next.clone()).await.unwrap();
        next
    }

    fn container_mmr_len(state: &MohoState, container_id: u8) -> u64 {
        state
            .export_state()
            .containers()
            .iter()
            .find(|c| c.container_id() == container_id)
            .unwrap()
            .entries_mmr()
            .num_entries()
    }

    fn verify_against(
        state: &MohoState,
        container_id: u8,
        proof: &MerkleProofB32,
        leaf: &[u8; 32],
    ) -> bool {
        state
            .export_state()
            .containers()
            .iter()
            .find(|c| c.container_id() == container_id)
            .unwrap()
            .entries_mmr()
            .verify(proof, leaf)
    }

    #[test]
    fn returns_proof_that_verifies_against_historical_mmr() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();

            // Two blocks each add two entries to the same container. Total 4.
            let b1 = commitment(100, 1);
            let state_at_b1 = apply_block(
                &moho,
                &idx,
                genesis_moho(),
                b1,
                &[
                    (CONTAINER_ID, entry_hash(0xa0)),
                    (CONTAINER_ID, entry_hash(0xa1)),
                ],
            )
            .await;
            let b2 = commitment(101, 2);
            let state_at_b2 = apply_block(
                &moho,
                &idx,
                state_at_b1,
                b2,
                &[
                    (CONTAINER_ID, entry_hash(0xa2)),
                    (CONTAINER_ID, entry_hash(0xa3)),
                ],
            )
            .await;

            let leaf = entry_hash(0xa2);
            let proof = build_export_entry_mmr_proof(&moho, &idx, b2, CONTAINER_ID, &leaf)
                .await
                .expect("proof should be present");

            assert_eq!(container_mmr_len(&state_at_b2, CONTAINER_ID), 4);
            assert!(
                verify_against(&state_at_b2, CONTAINER_ID, &proof, &leaf),
                "proof must verify against MohoState's compact MMR at the queried block"
            );
        });
    }

    #[test]
    fn proof_at_earlier_block_uses_that_blocks_mmr_size() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();

            let b1 = commitment(100, 1);
            let state_at_b1 = apply_block(
                &moho,
                &idx,
                genesis_moho(),
                b1,
                &[(CONTAINER_ID, entry_hash(0xa0))],
            )
            .await;
            let b2 = commitment(101, 2);
            apply_block(
                &moho,
                &idx,
                state_at_b1.clone(),
                b2,
                &[
                    (CONTAINER_ID, entry_hash(0xa1)),
                    (CONTAINER_ID, entry_hash(0xa2)),
                ],
            )
            .await;

            // Querying leaf 0xa0 at b1 must produce a proof valid against the
            // size-1 MMR, not the size-3 MMR at b2.
            let leaf = entry_hash(0xa0);
            let proof = build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &leaf)
                .await
                .unwrap();

            assert_eq!(container_mmr_len(&state_at_b1, CONTAINER_ID), 1);
            assert!(verify_against(&state_at_b1, CONTAINER_ID, &proof, &leaf));
        });
    }

    #[test]
    fn errors_when_leaf_inserted_after_queried_block() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();

            let b1 = commitment(100, 1);
            let state_at_b1 = apply_block(
                &moho,
                &idx,
                genesis_moho(),
                b1,
                &[(CONTAINER_ID, entry_hash(0xa0))],
            )
            .await;
            let b2 = commitment(101, 2);
            apply_block(
                &moho,
                &idx,
                state_at_b1,
                b2,
                &[(CONTAINER_ID, entry_hash(0xa1))],
            )
            .await;

            // 0xa1 was inserted at b2, so it is not covered by b1's MMR.
            let err =
                build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xa1))
                    .await
                    .unwrap_err();
            assert!(
                matches!(
                    err,
                    ExportProofError::LeafAfterBlock {
                        mmr_index: 1,
                        at_leaf_count: 1,
                        ..
                    }
                ),
                "expected LeafAfterBlock, got {err:?}"
            );
        });
    }

    #[test]
    fn errors_when_leaf_unknown() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let b1 = commitment(100, 1);
            apply_block(
                &moho,
                &idx,
                genesis_moho(),
                b1,
                &[(CONTAINER_ID, entry_hash(0xa0))],
            )
            .await;

            let err =
                build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xff))
                    .await
                    .unwrap_err();
            assert!(
                matches!(err, ExportProofError::NoSuchLeaf { .. }),
                "expected NoSuchLeaf, got {err:?}"
            );
        });
    }

    #[test]
    fn errors_when_container_missing() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let b1 = commitment(100, 1);
            apply_block(
                &moho,
                &idx,
                genesis_moho(),
                b1,
                &[(CONTAINER_ID, entry_hash(0xa0))],
            )
            .await;

            // A container that was never populated. Indistinguishable from one
            // that has not been created yet — both are legitimate absence.
            let err = build_export_entry_mmr_proof(&moho, &idx, b1, 99, &entry_hash(0xa0))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    ExportProofError::NoSuchContainer {
                        container_id: 99,
                        ..
                    }
                ),
                "expected NoSuchContainer, got {err:?}"
            );
        });
    }

    /// Drives the two stores out of sync on purpose: the index gets a leaf the
    /// state's MMR never absorbed, so the proof is well-formed but wrong.
    #[test]
    fn errors_when_proof_does_not_verify() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let b1 = commitment(100, 1);

            // The state records two entries for the container...
            let mut export = ExportState::new(vec![]).unwrap();
            export.add_entry(CONTAINER_ID, entry_hash(0xa0)).unwrap();
            export.add_entry(CONTAINER_ID, entry_hash(0xa1)).unwrap();
            let state = MohoState::new(
                InnerStateCommitment::from([0u8; 32]),
                PredicateKey::always_accept(),
                export,
            );
            moho.store_moho_state(b1, state).await.unwrap();

            // ...but the index mirrors a different second leaf. Both agree on
            // the count, so the size guard passes and the proof is built.
            idx.append_entries(CONTAINER_ID, b1.height(), vec![entry_hash(0xa0)])
                .await
                .unwrap();
            idx.append_entries(CONTAINER_ID, b1.height(), vec![entry_hash(0xbb)])
                .await
                .unwrap();

            let err =
                build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xbb))
                    .await
                    .unwrap_err();
            assert!(
                matches!(
                    err,
                    ExportProofError::ProofDoesNotVerify {
                        container_id: CONTAINER_ID,
                        mmr_index: 1,
                        ..
                    }
                ),
                "expected ProofDoesNotVerify, got {err:?}"
            );
        });
    }

    #[test]
    fn errors_when_state_missing() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let err = build_export_entry_mmr_proof(
                &moho,
                &idx,
                commitment(999, 9),
                CONTAINER_ID,
                &entry_hash(0xa0),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, ExportProofError::NoStateAtBlock(_)),
                "expected NoStateAtBlock, got {err:?}"
            );
        });
    }
}
