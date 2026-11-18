//! Index lookups and inclusion proofs for export entries, built from the two
//! Moho stores.
//!
//! [`MohoState`] keeps only each container's compact MMR, so both queries need
//! both stores: the state store fixes the MMR size at the queried block, and
//! the entry index supplies leaf positions and sibling hashes.

use std::fmt::Debug;

use moho_types::MohoState;
use strata_identifiers::L1BlockCommitment;
use strata_merkle::{MerkleProofB32, Mmr64B32};

use crate::{ExportEntriesDb, MohoStateDb};

/// Why an export-entry lookup or inclusion proof could not be resolved.
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

    /// The index is past the end of the container's MMR at the queried block.
    ///
    /// The entry index grows as the worker advances, while the historical
    /// state only ever saw the first `at_leaf_count` leaves.
    #[error(
        "index {mmr_index} is out of range for container {container_id}, which held \
         {at_leaf_count} entries at the queried block"
    )]
    IndexOutOfRange {
        /// The container that was queried.
        container_id: u8,
        /// The index that was queried.
        mmr_index: u64,
        /// How many leaves the container held at the queried block.
        at_leaf_count: u64,
    },

    /// The block's MMR counts a leaf at this index, but the entry index has
    /// none.
    ///
    /// Like [`ProofDoesNotVerify`](Self::ProofDoesNotVerify), the two stores
    /// disagree about the block.
    #[error(
        "container {container_id} has no indexed leaf at {mmr_index}, though the \
         mmr at {commitment:?} counts one"
    )]
    LeafNotIndexed {
        /// The container that was queried.
        container_id: u8,
        /// The index that was queried.
        mmr_index: u64,
        /// The block whose MMR counts the leaf.
        commitment: L1BlockCommitment,
    },

    /// The generated proof did not verify against the block's MMR.
    ///
    /// The two stores disagree: the entry index produced a proof that the
    /// state's compact MMR rejects. Neither input is attacker-controlled, so
    /// either the block was reorged out or the mirrored leaves have drifted.
    /// A reorged-out block keeps its stored state, while the entry index is
    /// pruned and re-appended to follow the canonical chain.
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

/// Finds the MMR index of `leaf` in `container_id`, as of `commitment`.
///
/// Returns `None` when the leaf is not part of the container's MMR at that
/// block: the container does not exist yet, the leaf was never indexed, or it
/// was appended after the block.
///
/// The lookup resolves to the most recent occurrence of `leaf`. If the same
/// hash was appended again after `commitment`, this returns `None` even when an
/// earlier copy is covered by the block's MMR.
///
/// # Errors
///
/// Errors when no Moho state is stored for `commitment`, or a store fails.
pub async fn find_export_entry_index<M, E>(
    moho_state_db: &M,
    export_entries_db: &E,
    commitment: L1BlockCommitment,
    container_id: u8,
    leaf: &[u8; 32],
) -> Result<Option<u64>, ExportProofError<M::Error, E::Error>>
where
    M: MohoStateDb,
    E: ExportEntriesDb,
{
    let moho_state = moho_state_db
        .get_moho_state(commitment)
        .await
        .map_err(ExportProofError::MohoState)?
        .ok_or(ExportProofError::NoStateAtBlock(commitment))?;

    let Some(mmr) = container_mmr(&moho_state, container_id) else {
        return Ok(None);
    };
    let at_leaf_count = mmr.num_entries();

    let mmr_index = export_entries_db
        .find_entry_index(container_id, *leaf)
        .await
        .map_err(ExportProofError::ExportEntries)?;

    Ok(mmr_index.filter(|&idx| idx < at_leaf_count))
}

/// Returns the export leaf hash at `mmr_index` and its inclusion proof as of `commitment`.
///
/// The returned hash and proof are verified together against the container's MMR in
/// the stored [`MohoState`]. Returning the verified hash avoids a second leaf read
/// that could observe a replacement chain after a reorg.
pub async fn build_export_entry_mmr_proof<M, E>(
    moho_state_db: &M,
    export_entries_db: &E,
    commitment: L1BlockCommitment,
    container_id: u8,
    mmr_index: u64,
) -> Result<([u8; 32], MerkleProofB32), ExportProofError<M::Error, E::Error>>
where
    M: MohoStateDb,
    E: ExportEntriesDb,
{
    let moho_state = moho_state_db
        .get_moho_state(commitment)
        .await
        .map_err(ExportProofError::MohoState)?
        .ok_or(ExportProofError::NoStateAtBlock(commitment))?;

    let mmr =
        container_mmr(&moho_state, container_id).ok_or(ExportProofError::NoSuchContainer {
            container_id,
            commitment,
        })?;
    let at_leaf_count = mmr.num_entries();

    if mmr_index >= at_leaf_count {
        return Err(ExportProofError::IndexOutOfRange {
            container_id,
            mmr_index,
            at_leaf_count,
        });
    }

    let leaf = export_entries_db
        .get_entry(container_id, mmr_index)
        .await
        .map_err(ExportProofError::ExportEntries)?
        .ok_or(ExportProofError::LeafNotIndexed {
            container_id,
            mmr_index,
            commitment,
        })?;

    let proof = export_entries_db
        .generate_entry_proof(container_id, mmr_index, at_leaf_count)
        .await
        .map_err(ExportProofError::ExportEntries)?;

    // The proof comes from the mirrored leaves, but it is consumed against the
    // state's compact MMR. Check it here so drift between the two stores fails
    // at the source rather than at whoever verifies it later.
    if !mmr.verify(&proof, &leaf) {
        return Err(ExportProofError::ProofDoesNotVerify {
            container_id,
            mmr_index,
            commitment,
        });
    }

    Ok((leaf, proof))
}

fn container_mmr(state: &MohoState, container_id: u8) -> Option<&Mmr64B32> {
    state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == container_id)
        .map(|c| c.entries_mmr())
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
            let mmr_index = find_export_entry_index(&moho, &idx, b2, CONTAINER_ID, &leaf)
                .await
                .unwrap();
            assert_eq!(mmr_index, Some(2));

            let (returned_leaf, proof) =
                build_export_entry_mmr_proof(&moho, &idx, b2, CONTAINER_ID, 2)
                    .await
                    .expect("proof should be present");

            assert_eq!(returned_leaf, leaf);
            assert_eq!(proof.index(), 2);
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

            // A proof for index 0 at b1 must be valid against the size-1 MMR,
            // not the size-3 MMR at b2.
            let (leaf, proof) = build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, 0)
                .await
                .unwrap();

            assert_eq!(leaf, entry_hash(0xa0));

            assert_eq!(container_mmr_len(&state_at_b1, CONTAINER_ID), 1);
            assert!(verify_against(
                &state_at_b1,
                CONTAINER_ID,
                &proof,
                &entry_hash(0xa0)
            ));
        });
    }

    #[test]
    fn leaf_inserted_after_queried_block_is_out_of_range() {
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
            let mmr_index =
                find_export_entry_index(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xa1))
                    .await
                    .unwrap();
            assert_eq!(mmr_index, None);

            let err = build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, 1)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    ExportProofError::IndexOutOfRange {
                        mmr_index: 1,
                        at_leaf_count: 1,
                        ..
                    }
                ),
                "expected IndexOutOfRange, got {err:?}"
            );
        });
    }

    #[test]
    fn unknown_leaf_has_no_index() {
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

            let mmr_index =
                find_export_entry_index(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xff))
                    .await
                    .unwrap();
            assert_eq!(mmr_index, None);
        });
    }

    #[test]
    fn missing_container_has_no_index_and_no_proof() {
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
            let mmr_index = find_export_entry_index(&moho, &idx, b1, 99, &entry_hash(0xa0))
                .await
                .unwrap();
            assert_eq!(mmr_index, None);

            let err = build_export_entry_mmr_proof(&moho, &idx, b1, 99, 0)
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

    /// The lookup resolves to the latest copy of a hash, so a copy appended
    /// after the queried block hides an earlier one that block does cover.
    #[test]
    fn later_duplicate_hides_earlier_copy() {
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
                &[(CONTAINER_ID, entry_hash(0xa0))],
            )
            .await;

            let leaf = entry_hash(0xa0);
            let at_b1 = find_export_entry_index(&moho, &idx, b1, CONTAINER_ID, &leaf)
                .await
                .unwrap();
            let at_b2 = find_export_entry_index(&moho, &idx, b2, CONTAINER_ID, &leaf)
                .await
                .unwrap();
            assert_eq!(at_b1, None);
            assert_eq!(at_b2, Some(1));
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
            idx.append_entries(
                CONTAINER_ID,
                b1.height(),
                vec![entry_hash(0xa0), entry_hash(0xbb)],
            )
            .await
            .unwrap();

            let err = build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, 1)
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

    /// The state counts more leaves than the index mirrors.
    #[test]
    fn errors_when_leaf_not_indexed() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let b1 = commitment(100, 1);

            let mut export = ExportState::new(vec![]).unwrap();
            export.add_entry(CONTAINER_ID, entry_hash(0xa0)).unwrap();
            export.add_entry(CONTAINER_ID, entry_hash(0xa1)).unwrap();
            let state = MohoState::new(
                InnerStateCommitment::from([0u8; 32]),
                PredicateKey::always_accept(),
                export,
            );
            moho.store_moho_state(b1, state).await.unwrap();

            idx.append_entries(CONTAINER_ID, b1.height(), vec![entry_hash(0xa0)])
                .await
                .unwrap();

            let err = build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, 1)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    ExportProofError::LeafNotIndexed {
                        container_id: CONTAINER_ID,
                        mmr_index: 1,
                        ..
                    }
                ),
                "expected LeafNotIndexed, got {err:?}"
            );
        });
    }

    #[test]
    fn errors_when_state_missing() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let at = commitment(999, 9);

            let err = find_export_entry_index(&moho, &idx, at, CONTAINER_ID, &entry_hash(0xa0))
                .await
                .unwrap_err();
            assert!(
                matches!(err, ExportProofError::NoStateAtBlock(_)),
                "expected NoStateAtBlock, got {err:?}"
            );

            let err = build_export_entry_mmr_proof(&moho, &idx, at, CONTAINER_ID, 0)
                .await
                .unwrap_err();
            assert!(
                matches!(err, ExportProofError::NoStateAtBlock(_)),
                "expected NoStateAtBlock, got {err:?}"
            );
        });
    }
}
