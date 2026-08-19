//! Inclusion proofs for export entries, built from the two Moho stores.
//!
//! [`MohoState`](moho_types::MohoState) keeps only each container's compact MMR,
//! so a proof needs both stores: the state store fixes the MMR size at the
//! queried block, and the entry index supplies the leaf position and the
//! sibling hashes.

use std::fmt::Debug;

use ssz::Encode;
use strata_identifiers::L1BlockCommitment;

use crate::{ExportEntriesDb, MohoStateDb};

/// Failure while building an export-entry inclusion proof.
///
/// Each variant carries the originating store's error. The traits only require
/// [`Debug`] of them, so that is what is rendered.
#[derive(Debug, thiserror::Error)]
pub enum ExportProofError<M: Debug, E: Debug> {
    /// The Moho state store failed.
    #[error("moho state store: {0:?}")]
    MohoState(M),

    /// The export-entry index failed.
    #[error("export entry index: {0:?}")]
    ExportEntries(E),
}

/// Builds an SSZ-encoded MMR inclusion proof for `leaf` in `container_id`, as of
/// `commitment`.
///
/// Resolves to `None` when the leaf or the container is not part of that
/// snapshot yet; `Err` only for storage failures.
pub async fn build_export_entry_mmr_proof<M, E>(
    moho_state_db: &M,
    export_entries_db: &E,
    commitment: L1BlockCommitment,
    container_id: u8,
    leaf: &[u8; 32],
) -> Result<Option<Vec<u8>>, ExportProofError<M::Error, E::Error>>
where
    M: MohoStateDb,
    E: ExportEntriesDb,
{
    let Some(moho_state) = moho_state_db
        .get_moho_state(commitment)
        .await
        .map_err(ExportProofError::MohoState)?
    else {
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

    let Some(mmr_index) = export_entries_db
        .find_entry_index(container_id, *leaf)
        .await
        .map_err(ExportProofError::ExportEntries)?
    else {
        return Ok(None);
    };

    // Guard against entries appended after `commitment`: the index is populated
    // monotonically by the worker, but the historical `MohoState` only saw the
    // first `at_leaf_count` of them.
    if mmr_index >= at_leaf_count {
        return Ok(None);
    }

    let proof = export_entries_db
        .generate_entry_proof(container_id, mmr_index, at_leaf_count)
        .await
        .map_err(ExportProofError::ExportEntries)?;

    Ok(Some(proof.as_ssz_bytes()))
}

#[cfg(test)]
mod tests {
    //! Tests against real sled storage, mirroring the worker's invariant: each
    //! new export entry hits both `ExportState` and the entry index, in order.
    use moho_types::{ExportState, InnerStateCommitment, MohoState};
    use ssz::Decode;
    use strata_identifiers::{Buf32, L1BlockId};
    use strata_merkle::MerkleProofB32;
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

    fn verify_against(state: &MohoState, container_id: u8, bytes: &[u8], leaf: &[u8; 32]) -> bool {
        let proof = MerkleProofB32::from_ssz_bytes(bytes).unwrap();
        state
            .export_state()
            .containers()
            .iter()
            .find(|c| c.container_id() == container_id)
            .unwrap()
            .entries_mmr()
            .verify(&proof, leaf)
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
            let bytes = build_export_entry_mmr_proof(&moho, &idx, b2, CONTAINER_ID, &leaf)
                .await
                .unwrap()
                .expect("proof should be present");

            assert_eq!(container_mmr_len(&state_at_b2, CONTAINER_ID), 4);
            assert!(
                verify_against(&state_at_b2, CONTAINER_ID, &bytes, &leaf),
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
            let bytes = build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &leaf)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(container_mmr_len(&state_at_b1, CONTAINER_ID), 1);
            assert!(verify_against(&state_at_b1, CONTAINER_ID, &bytes, &leaf));
        });
    }

    #[test]
    fn none_when_leaf_inserted_after_queried_block() {
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

            // 0xa1 was inserted at b2, so it is absent as of b1.
            let out =
                build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xa1))
                    .await
                    .unwrap();
            assert!(out.is_none());
        });
    }

    #[test]
    fn none_when_leaf_unknown() {
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

            let out =
                build_export_entry_mmr_proof(&moho, &idx, b1, CONTAINER_ID, &entry_hash(0xff))
                    .await
                    .unwrap();
            assert!(out.is_none());
        });
    }

    #[test]
    fn none_when_container_missing() {
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
            let out = build_export_entry_mmr_proof(&moho, &idx, b1, 99, &entry_hash(0xa0))
                .await
                .unwrap();
            assert!(out.is_none());
        });
    }

    #[test]
    fn none_when_state_missing() {
        Runtime::new().unwrap().block_on(async {
            let (moho, idx, _tmp) = temp_dbs();
            let out = build_export_entry_mmr_proof(
                &moho,
                &idx,
                commitment(999, 9),
                CONTAINER_ID,
                &entry_hash(0xa0),
            )
            .await
            .unwrap();
            assert!(out.is_none());
        });
    }
}
