//! [`RemoteProofMappingDb`] implementation for [`SledProofDb`].

use std::{collections::BTreeSet, error::Error, fmt};

use borsh::BorshDeserialize;
use strata_asm_prover_types::{ProofId, RemoteProofId};

use super::SledProofDb;
use crate::RemoteProofMappingDb;

/// Errors returned by the sled-backed [`RemoteProofMappingDb`] implementation.
#[derive(Debug)]
pub enum RemoteProofMappingError {
    /// The underlying sled database returned an error.
    Db(sled::Error),
    /// The given [`RemoteProofId`] is already associated with a different
    /// [`ProofId`].
    DuplicateRemoteId {
        /// The remote proof ID that was already mapped.
        remote_id: RemoteProofId,
        /// The [`ProofId`] that `remote_id` is already mapped to.
        existing: ProofId,
        /// The [`ProofId`] that was passed to `put_remote_proof_id`.
        attempted: ProofId,
    },
}

impl fmt::Display for RemoteProofMappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(e) => write!(f, "sled error: {e}"),
            Self::DuplicateRemoteId {
                remote_id,
                existing,
                attempted,
            } => write!(
                f,
                "remote proof ID {remote_id:?} is already mapped to {existing:?}, \
                 cannot remap to {attempted:?}"
            ),
        }
    }
}

impl Error for RemoteProofMappingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sled::Error> for RemoteProofMappingError {
    fn from(e: sled::Error) -> Self {
        Self::Db(e)
    }
}

/// Synchronous mapping accessors, for offline tooling that stays synchronous.
///
/// The read half of [`RemoteProofMappingDb`] delegates to these; `list_mappings`
/// has no async-trait counterpart and exists only for that tooling.
impl SledProofDb {
    /// Returns the remote proof ID mapped to local `id`, if any.
    pub fn get_remote(&self, id: ProofId) -> Result<Option<RemoteProofId>, sled::Error> {
        if let Some(job) = self
            .active_remote_job(id)
            .map_err(|error| sled::Error::Unsupported(error.to_string()))?
        {
            return Ok(Some(job.remote_id));
        }
        // A terminal authoritative job deliberately has no active mapping.
        // Do not let its retained legacy forward row resurrect it for offline
        // tooling after migration.
        if self
            .list_remote_jobs()
            .map_err(|error| sled::Error::Unsupported(error.to_string()))?
            .iter()
            .any(|job| job.proof_id == id)
        {
            return Ok(None);
        }
        let key = borsh::to_vec(&id).expect("borsh serialization should not fail");
        Ok(self
            .proof_to_remote
            .get(key)?
            .map(|v| RemoteProofId(v.to_vec())))
    }

    /// Returns the local proof ID mapped to `remote_id`, if any.
    pub fn get_local(&self, remote_id: &RemoteProofId) -> Result<Option<ProofId>, sled::Error> {
        if let Some(job) = self
            .remote_job(remote_id)
            .map_err(|error| sled::Error::Unsupported(error.to_string()))?
        {
            return Ok(Some(job.proof_id));
        }
        Ok(self.remote_to_proof.get(&remote_id.0)?.map(|v| {
            BorshDeserialize::try_from_slice(&v).expect("stored ProofId should be valid borsh")
        }))
    }

    /// Clears `remote_id` from the active forward mapping for `id`.
    ///
    /// The compare-and-swap makes a late terminal update harmless after a
    /// replacement job has already become active. The reverse mapping is kept
    /// as append-only audit history.
    pub fn deactivate_remote(
        &self,
        id: ProofId,
        remote_id: &RemoteProofId,
    ) -> Result<(), sled::Error> {
        let proof_key = borsh::to_vec(&id).expect("borsh serialization should not fail");
        let _ = self.proof_to_remote.compare_and_swap(
            proof_key,
            Some(remote_id.0.as_slice()),
            None as Option<&[u8]>,
        )?;
        Ok(())
    }

    /// Lists every stored mapping as `(local, remote)` pairs.
    ///
    /// Iterates the reverse (`remote → local`) index, which holds one row per
    /// remote id; the forward index can point several proof ids at the latest
    /// remote id on resubmission, so it is not authoritative for enumeration.
    pub fn list_mappings(&self) -> Result<Vec<(ProofId, RemoteProofId)>, sled::Error> {
        let mut mappings: BTreeSet<_> = self
            .list_remote_jobs()
            .map_err(|error| sled::Error::Unsupported(error.to_string()))?
            .into_iter()
            .map(|job| (job.proof_id, job.remote_id))
            .collect();
        mappings.extend(
            self.remote_to_proof
                .iter()
                .map(|entry| {
                    let (remote_bytes, local_bytes) = entry?;
                    let local: ProofId = BorshDeserialize::try_from_slice(&local_bytes)
                        .expect("stored ProofId should be valid borsh");
                    Ok((local, RemoteProofId(remote_bytes.to_vec())))
                })
                .collect::<Result<BTreeSet<_>, sled::Error>>()?,
        );
        Ok(mappings.into_iter().collect())
    }
}

impl RemoteProofMappingDb for SledProofDb {
    type Error = RemoteProofMappingError;

    async fn get_remote_proof_id(&self, id: ProofId) -> Result<Option<RemoteProofId>, Self::Error> {
        Ok(self.get_remote(id)?)
    }

    async fn get_proof_id(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<ProofId>, Self::Error> {
        Ok(self.get_local(remote_id)?)
    }

    async fn put_remote_proof_id(
        &self,
        id: ProofId,
        remote_id: RemoteProofId,
    ) -> Result<(), Self::Error> {
        let proof_key = borsh::to_vec(&id).expect("borsh serialization should not fail");

        // Claim the globally unique remote ID first. If this is a historical
        // ID for the same proof, it may reactivate an absent forward mapping,
        // but must never replace a newer retry that is already active.
        let reverse = self.remote_to_proof.compare_and_swap(
            remote_id.0.as_slice(),
            None as Option<&[u8]>,
            Some(proof_key.as_slice()),
        )?;
        match reverse {
            Ok(()) => {
                // A genuinely new remote job becomes the latest active job.
                // If the process stops before this insert, retrying the same
                // pair takes the historical-ID branch below and repairs the
                // absent forward row.
                self.proof_to_remote
                    .insert(proof_key.as_slice(), remote_id.0.as_slice())?;
            }
            Err(conflict) => {
                let existing_bytes = conflict
                    .current
                    .expect("compare-and-swap conflict must contain the existing reverse row");
                let existing: ProofId = BorshDeserialize::try_from_slice(&existing_bytes)
                    .expect("stored ProofId should be valid borsh");
                if existing != id {
                    return Err(RemoteProofMappingError::DuplicateRemoteId {
                        remote_id,
                        existing,
                        attempted: id,
                    });
                }

                // The same remote ID is being replayed after deactivation (or
                // after a crash between the reverse and forward writes). It
                // may fill an empty forward slot, but a different current ID
                // is a newer retry and wins.
                let _ = self.proof_to_remote.compare_and_swap(
                    proof_key.as_slice(),
                    None as Option<&[u8]>,
                    Some(remote_id.0.as_slice()),
                )?;
            }
        }
        Ok(())
    }

    async fn deactivate_remote_proof_id(
        &self,
        id: ProofId,
        remote_id: &RemoteProofId,
    ) -> Result<(), Self::Error> {
        Ok(self.deactivate_remote(id, remote_id)?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::{collection::vec, prelude::*};
    use strata_asm_prover_types::ProofId;
    use strata_identifiers::{L1BlockCommitment, L1BlockId};
    use tokio::runtime::Runtime;
    use zkaleido::RemoteProofStatus;

    use super::*;
    use crate::{RemoteProofStatusDb, sled::test_util::*};

    /// Generates an arbitrary [`ProofId`].
    fn arb_proof_id() -> impl Strategy<Value = ProofId> {
        prop_oneof![
            arb_l1_range().prop_map(ProofId::Asm),
            arb_l1_block_commitment().prop_map(ProofId::Moho),
        ]
    }

    /// Generates an arbitrary [`RemoteProofId`].
    fn arb_remote_proof_id() -> impl Strategy<Value = RemoteProofId> {
        vec(any::<u8>(), 1..64).prop_map(RemoteProofId)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: a stored mapping can be looked up in both directions.
        #[test]
        fn remote_proof_mapping_roundtrip(
            proof_id in arb_proof_id(),
            remote_id in arb_remote_proof_id(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_remote_proof_id(proof_id, remote_id.clone()).await.unwrap();

                let got_remote = db.get_remote_proof_id(proof_id).await.unwrap();
                prop_assert_eq!(got_remote.as_ref(), Some(&remote_id));

                let got_local = db.get_proof_id(&remote_id).await.unwrap();
                prop_assert_eq!(got_local, Some(proof_id));

                Ok(())
            })?;
        }

        /// Property: looking up a proof ID that was never stored returns None.
        #[test]
        fn remote_proof_mapping_missing_returns_none(
            proof_id in arb_proof_id(),
            remote_id in arb_remote_proof_id(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                let got_remote = db.get_remote_proof_id(proof_id).await.unwrap();
                prop_assert_eq!(got_remote, None);

                let got_local = db.get_proof_id(&remote_id).await.unwrap();
                prop_assert_eq!(got_local, None);

                Ok(())
            })?;
        }

        /// Property: the same proof ID can be mapped to multiple remote IDs
        /// (resubmission). The forward lookup returns the latest remote ID,
        /// and all reverse lookups remain valid.
        #[test]
        fn remote_proof_mapping_resubmit(
            proof_id in arb_proof_id(),
            remote_id_1 in arb_remote_proof_id(),
            remote_id_2 in arb_remote_proof_id(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_remote_proof_id(proof_id, remote_id_1.clone()).await.unwrap();
                db.put_remote_proof_id(proof_id, remote_id_2.clone()).await.unwrap();

                // Forward lookup returns the latest remote ID.
                let got_remote = db.get_remote_proof_id(proof_id).await.unwrap();
                prop_assert_eq!(got_remote.as_ref(), Some(&remote_id_2));

                // Both reverse lookups resolve to the same proof ID.
                let got_local_1 = db.get_proof_id(&remote_id_1).await.unwrap();
                prop_assert_eq!(got_local_1, Some(proof_id));

                let got_local_2 = db.get_proof_id(&remote_id_2).await.unwrap();
                prop_assert_eq!(got_local_2, Some(proof_id));

                Ok(())
            })?;
        }

        /// Property: attempting to map an already-used remote ID to a
        /// *different* proof ID returns an error.
        #[test]
        fn remote_proof_mapping_duplicate_remote_id_errors(
            proof_id_1 in arb_proof_id(),
            proof_id_2 in arb_proof_id(),
            remote_id in arb_remote_proof_id(),
        ) {
            prop_assume!(proof_id_1 != proof_id_2);
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_remote_proof_id(proof_id_1, remote_id.clone()).await.unwrap();

                let result = db.put_remote_proof_id(proof_id_2, remote_id).await;
                prop_assert!(
                    matches!(result, Err(RemoteProofMappingError::DuplicateRemoteId { .. })),
                    "expected DuplicateRemoteId error, got {:?}", result,
                );

                Ok(())
            })?;
        }

        /// Property: re-inserting the exact same (proof_id, remote_id) pair is
        /// a no-op and does not error.
        #[test]
        fn remote_proof_mapping_idempotent(
            proof_id in arb_proof_id(),
            remote_id in arb_remote_proof_id(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_remote_proof_id(proof_id, remote_id.clone()).await.unwrap();
                db.put_remote_proof_id(proof_id, remote_id.clone()).await.unwrap();

                let got_remote = db.get_remote_proof_id(proof_id).await.unwrap();
                prop_assert_eq!(got_remote.as_ref(), Some(&remote_id));

                Ok(())
            })?;
        }

        /// Property: multiple distinct proof IDs can each have their own remote mapping.
        #[test]
        fn remote_proof_mapping_multiple_entries(
            entries in vec((arb_proof_id(), arb_remote_proof_id()), 2..10)
                .prop_filter("proof IDs must be unique",
                    |es| {
                        let ids: HashSet<_> = es.iter().map(|(p, _)| p).collect();
                        ids.len() == es.len()
                    })
                .prop_filter("remote IDs must be unique",
                    |es| {
                        let ids: HashSet<_> = es.iter().map(|(_, r)| r).collect();
                        ids.len() == es.len()
                    })
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                for (proof_id, remote_id) in &entries {
                    db.put_remote_proof_id(*proof_id, remote_id.clone()).await.unwrap();
                }

                for (proof_id, remote_id) in &entries {
                    let got_remote = db.get_remote_proof_id(*proof_id).await.unwrap();
                    prop_assert_eq!(got_remote.as_ref(), Some(remote_id));

                    let got_local = db.get_proof_id(remote_id).await.unwrap();
                    prop_assert_eq!(got_local, Some(*proof_id));
                }

                Ok(())
            })?;
        }

        /// Property: `list_mappings` enumerates every stored `(local, remote)` pair.
        #[test]
        fn list_mappings_enumerates_all(
            entries in vec((arb_proof_id(), arb_remote_proof_id()), 1..8)
                .prop_filter("proof IDs must be unique",
                    |es| es.iter().map(|(p, _)| p).collect::<HashSet<_>>().len() == es.len())
                .prop_filter("remote IDs must be unique",
                    |es| es.iter().map(|(_, r)| r).collect::<HashSet<_>>().len() == es.len())
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                for (proof_id, remote_id) in &entries {
                    db.put_remote_proof_id(*proof_id, remote_id.clone()).await.unwrap();
                }

                let expected: HashSet<_> = entries.iter().map(|(p, r)| (*p, r.clone())).collect();
                let got: HashSet<_> = db.list_mappings().unwrap().into_iter().collect();
                prop_assert_eq!(got, expected);

                Ok(())
            })?;
        }
    }

    #[tokio::test]
    async fn failed_job_becomes_resubmittable_without_losing_reverse_history() {
        let (db, _dir) = temp_db();
        let proof_id = ProofId::Moho(L1BlockCommitment::new(42, L1BlockId::default()));
        let failed_remote = RemoteProofId(vec![0xfa]);
        let retry_remote = RemoteProofId(vec![0xfb]);

        // requested
        db.put_remote_proof_id(proof_id, failed_remote.clone())
            .await
            .unwrap();
        db.put_status(&failed_remote, RemoteProofStatus::Requested)
            .await
            .unwrap();

        // failed: release deduplication first, then remove active tracking.
        db.deactivate_remote_proof_id(proof_id, &failed_remote)
            .await
            .unwrap();
        db.remove(&failed_remote).await.unwrap();

        assert_eq!(db.get_remote_proof_id(proof_id).await.unwrap(), None);
        assert_eq!(
            db.get_proof_id(&failed_remote).await.unwrap(),
            Some(proof_id),
            "the reverse row remains available for audit",
        );
        assert_eq!(db.get_status(&failed_remote).await.unwrap(), None);
        assert!(db.get_all_in_progress().await.unwrap().is_empty());

        // retry: the same local proof accepts a new active remote job.
        db.put_remote_proof_id(proof_id, retry_remote.clone())
            .await
            .unwrap();
        db.put_status(&retry_remote, RemoteProofStatus::Requested)
            .await
            .unwrap();

        assert_eq!(
            db.get_remote_proof_id(proof_id).await.unwrap(),
            Some(retry_remote.clone()),
        );
        assert_eq!(
            db.get_proof_id(&retry_remote).await.unwrap(),
            Some(proof_id),
        );
        assert_eq!(
            db.get_all_in_progress().await.unwrap(),
            vec![(retry_remote.clone(), RemoteProofStatus::Requested)],
        );

        // A late duplicate failure event for the old job cannot clear the
        // replacement mapping.
        db.deactivate_remote_proof_id(proof_id, &failed_remote)
            .await
            .unwrap();
        assert_eq!(
            db.get_remote_proof_id(proof_id).await.unwrap(),
            Some(retry_remote),
        );
    }

    #[tokio::test]
    async fn reusing_a_deactivated_remote_id_reactivates_only_an_empty_forward_slot() {
        let (db, _dir) = temp_db();
        let proof_id = ProofId::Moho(L1BlockCommitment::new(42, L1BlockId::default()));
        let old_remote = RemoteProofId(vec![0xfa]);
        let replacement = RemoteProofId(vec![0xfb]);

        db.put_remote_proof_id(proof_id, old_remote.clone())
            .await
            .unwrap();
        db.deactivate_remote_proof_id(proof_id, &old_remote)
            .await
            .unwrap();

        // Replaying the exact pair repairs an absent forward mapping.
        db.put_remote_proof_id(proof_id, old_remote.clone())
            .await
            .unwrap();
        assert_eq!(
            db.get_remote_proof_id(proof_id).await.unwrap(),
            Some(old_remote.clone()),
        );

        db.deactivate_remote_proof_id(proof_id, &old_remote)
            .await
            .unwrap();
        db.put_remote_proof_id(proof_id, replacement.clone())
            .await
            .unwrap();

        // Replaying the old pair after a replacement is active is harmless.
        db.put_remote_proof_id(proof_id, old_remote.clone())
            .await
            .unwrap();
        db.deactivate_remote_proof_id(proof_id, &old_remote)
            .await
            .unwrap();
        assert_eq!(
            db.get_remote_proof_id(proof_id).await.unwrap(),
            Some(replacement),
        );
    }
}
