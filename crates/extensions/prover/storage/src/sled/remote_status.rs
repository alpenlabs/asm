//! [`RemoteProofStatusDb`] implementation for [`SledProofDb`].

use std::{error::Error, fmt};

use borsh::BorshDeserialize;
use strata_asm_prover_types::{ProofId, RemoteProofId};
use zkaleido::RemoteProofStatus;

use super::SledProofDb;
use crate::RemoteProofStatusDb;

/// Errors returned by the sled-backed [`RemoteProofStatusDb`] implementation.
#[derive(Debug)]
pub enum RemoteProofStatusError {
    /// The underlying sled database returned an error.
    Db(sled::Error),
    /// Attempted to insert a status for a remote proof ID that already exists.
    AlreadyExists(RemoteProofId),
    /// Attempted to update a status for a remote proof ID that does not exist.
    NotFound(RemoteProofId),
}

impl fmt::Display for RemoteProofStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(e) => write!(f, "sled error: {e}"),
            Self::AlreadyExists(id) => {
                write!(f, "status entry already exists for remote proof ID {id:?}")
            }
            Self::NotFound(id) => {
                write!(f, "no status entry found for remote proof ID {id:?}")
            }
        }
    }
}

impl Error for RemoteProofStatusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sled::Error> for RemoteProofStatusError {
    fn from(e: sled::Error) -> Self {
        Self::Db(e)
    }
}

/// Synchronous status accessors, for offline tooling that stays synchronous.
///
/// The read/remove half of [`RemoteProofStatusDb`] delegates to these; the names
/// differ from the trait's so a delegating call is unambiguous. `list_status`
/// (every entry, not just active ones) has no async-trait counterpart, and
/// `prune_status_before` is the status half of [`SledProofDb::prune_before`].
impl SledProofDb {
    /// Returns the tracked status of `remote_id`, if any.
    pub fn status(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<RemoteProofStatus>, sled::Error> {
        Ok(self.remote_proof_status.get(&remote_id.0)?.map(|v| {
            BorshDeserialize::try_from_slice(&v)
                .expect("stored RemoteProofStatus should be valid borsh")
        }))
    }

    /// Lists every tracked `(remote_id, status)` pair.
    pub fn list_status(&self) -> Result<Vec<(RemoteProofId, RemoteProofStatus)>, sled::Error> {
        self.remote_proof_status
            .iter()
            .map(|entry| {
                let (k, v) = entry?;
                let status: RemoteProofStatus = BorshDeserialize::try_from_slice(&v)
                    .expect("stored RemoteProofStatus should be valid borsh");
                Ok((RemoteProofId(k.to_vec()), status))
            })
            .collect()
    }

    /// Lists the currently active (`Requested` or `InProgress`) jobs.
    pub fn in_progress(&self) -> Result<Vec<(RemoteProofId, RemoteProofStatus)>, sled::Error> {
        Ok(self
            .list_status()?
            .into_iter()
            .filter(|(_, status)| {
                matches!(
                    status,
                    RemoteProofStatus::Requested | RemoteProofStatus::InProgress
                )
            })
            .collect())
    }

    /// Removes the status entry for `remote_id`, returning whether one was present.
    pub fn delete_status(&self, remote_id: &RemoteProofId) -> Result<bool, sled::Error> {
        Ok(self.remote_proof_status.remove(&remote_id.0)?.is_some())
    }

    /// Removes the status rows of proofs below `before_height`, returning how
    /// many were removed and how many were left in place.
    ///
    /// A status row is keyed by remote id and carries no height, so its height
    /// comes from the proof the reverse mapping resolves it to. A row whose
    /// remote id has no mapping cannot be placed at any height, so it is left
    /// alone and counted separately — the caller surfaces it rather than
    /// guessing which side of the cutoff it belongs on.
    ///
    /// The count of orphans covers the whole tree, not just the pruned range,
    /// for the same reason: their heights are exactly what is unknown.
    pub(crate) fn prune_status_before(
        &self,
        before_height: u32,
    ) -> Result<(usize, usize), sled::Error> {
        let mut stale = Vec::new();
        let mut orphans = 0;

        for key in self.remote_proof_status.iter().keys() {
            let key = key?;
            match self.remote_to_proof.get(&key)? {
                Some(local_bytes) => {
                    let local: ProofId = BorshDeserialize::try_from_slice(&local_bytes)
                        .expect("stored ProofId should be valid borsh");
                    if local.height() < before_height {
                        stale.push(key);
                    }
                }
                None => orphans += 1,
            }
        }

        let removed = stale.len();
        for key in stale {
            self.remote_proof_status.remove(key)?;
        }
        Ok((removed, orphans))
    }
}

impl RemoteProofStatusDb for SledProofDb {
    type Error = RemoteProofStatusError;

    async fn put_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        let bytes = borsh::to_vec(&status).expect("borsh serialization should not fail");
        let result = self.remote_proof_status.compare_and_swap(
            &remote_id.0,
            None as Option<&[u8]>,
            Some(bytes),
        )?;
        match result {
            Ok(()) => Ok(()),
            Err(_) => Err(RemoteProofStatusError::AlreadyExists(remote_id.clone())),
        }
    }

    async fn update_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        let bytes = borsh::to_vec(&status).expect("borsh serialization should not fail");
        let old = self
            .remote_proof_status
            .fetch_and_update(&remote_id.0, |existing| existing.map(|_| bytes.clone()))?;
        match old {
            Some(_) => Ok(()),
            None => Err(RemoteProofStatusError::NotFound(remote_id.clone())),
        }
    }

    async fn get_status(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<RemoteProofStatus>, Self::Error> {
        Ok(self.status(remote_id)?)
    }

    async fn get_all_in_progress(
        &self,
    ) -> Result<Vec<(RemoteProofId, RemoteProofStatus)>, Self::Error> {
        Ok(self.in_progress()?)
    }

    async fn remove(&self, remote_id: &RemoteProofId) -> Result<(), Self::Error> {
        self.delete_status(remote_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::{collection::vec, prelude::*};
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use tokio::runtime::Runtime;
    use zkaleido::RemoteProofFailureReason;

    use super::*;
    use crate::{RemoteProofMappingDb, sled::test_util::*};

    /// A commitment at `height` with a fixed block id, for the tests that care
    /// about heights rather than identity.
    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::new([0; 32])))
    }

    /// Generates an arbitrary [`RemoteProofId`].
    fn arb_remote_proof_id() -> impl Strategy<Value = RemoteProofId> {
        vec(any::<u8>(), 1..64).prop_map(RemoteProofId)
    }

    /// Generates an arbitrary [`RemoteProofFailureReason`].
    fn arb_failure_reason() -> impl Strategy<Value = RemoteProofFailureReason> {
        prop_oneof![
            Just(RemoteProofFailureReason::Unexecutable),
            Just(RemoteProofFailureReason::Unfulfillable),
            Just(RemoteProofFailureReason::Reverted),
            Just(RemoteProofFailureReason::Expired),
            ".*".prop_map(RemoteProofFailureReason::Other),
        ]
    }

    /// Generates an arbitrary [`RemoteProofStatus`].
    fn arb_remote_proof_status() -> impl Strategy<Value = RemoteProofStatus> {
        prop_oneof![
            Just(RemoteProofStatus::Requested),
            Just(RemoteProofStatus::InProgress),
            Just(RemoteProofStatus::Completed),
            arb_failure_reason().prop_map(RemoteProofStatus::Failed),
        ]
    }

    /// Generates a status that counts as "in progress" for `get_all_in_progress`.
    fn arb_active_status() -> impl Strategy<Value = RemoteProofStatus> {
        prop_oneof![
            Just(RemoteProofStatus::Requested),
            Just(RemoteProofStatus::InProgress),
        ]
    }

    /// Generates a status that is **not** active.
    fn arb_terminal_status() -> impl Strategy<Value = RemoteProofStatus> {
        prop_oneof![
            Just(RemoteProofStatus::Completed),
            arb_failure_reason().prop_map(RemoteProofStatus::Failed),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: a stored status can be retrieved.
        #[test]
        fn status_put_get_roundtrip(
            remote_id in arb_remote_proof_id(),
            status in arb_remote_proof_status(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_status(&remote_id, status.clone()).await.unwrap();

                let got = db.get_status(&remote_id).await.unwrap();
                prop_assert_eq!(got, Some(status));

                Ok(())
            })?;
        }

        /// Property: `put_status` errors when the entry already exists.
        #[test]
        fn status_put_duplicate_errors(
            remote_id in arb_remote_proof_id(),
            status1 in arb_remote_proof_status(),
            status2 in arb_remote_proof_status(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_status(&remote_id, status1).await.unwrap();

                let result = db.put_status(&remote_id, status2).await;
                prop_assert!(
                    matches!(result, Err(RemoteProofStatusError::AlreadyExists(_))),
                    "expected AlreadyExists error, got {:?}", result,
                );

                Ok(())
            })?;
        }

        /// Property: `update_status` replaces the status of an existing entry.
        #[test]
        fn status_update_roundtrip(
            remote_id in arb_remote_proof_id(),
            initial in arb_remote_proof_status(),
            updated in arb_remote_proof_status(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_status(&remote_id, initial).await.unwrap();
                db.update_status(&remote_id, updated.clone()).await.unwrap();

                let got = db.get_status(&remote_id).await.unwrap();
                prop_assert_eq!(got, Some(updated));

                Ok(())
            })?;
        }

        /// Property: `update_status` errors when no entry exists.
        #[test]
        fn status_update_missing_errors(
            remote_id in arb_remote_proof_id(),
            status in arb_remote_proof_status(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                let result = db.update_status(&remote_id, status).await;
                prop_assert!(
                    matches!(result, Err(RemoteProofStatusError::NotFound(_))),
                    "expected NotFound error, got {:?}", result,
                );

                Ok(())
            })?;
        }

        /// Property: `get_status` returns `None` for unknown remote IDs.
        #[test]
        fn status_get_missing_returns_none(remote_id in arb_remote_proof_id()) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                let got = db.get_status(&remote_id).await.unwrap();
                prop_assert_eq!(got, None);

                Ok(())
            })?;
        }

        /// Property: `remove` deletes the entry so subsequent `get_status` returns `None`.
        #[test]
        fn status_remove(
            remote_id in arb_remote_proof_id(),
            status in arb_remote_proof_status(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.put_status(&remote_id, status).await.unwrap();
                db.remove(&remote_id).await.unwrap();

                let got = db.get_status(&remote_id).await.unwrap();
                prop_assert_eq!(got, None);

                Ok(())
            })?;
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Property: `get_all_in_progress` returns exactly the entries with
        /// `Requested` or `InProgress` status.
        #[test]
        fn status_get_all_in_progress(
            active in vec((arb_remote_proof_id(), arb_active_status()), 1..5)
                .prop_filter("unique remote IDs",
                    |es| {
                        let ids: HashSet<_> = es.iter().map(|(r, _)| r).collect();
                        ids.len() == es.len()
                    }),
            terminal in vec((arb_remote_proof_id(), arb_terminal_status()), 1..5)
                .prop_filter("unique remote IDs",
                    |es| {
                        let ids: HashSet<_> = es.iter().map(|(r, _)| r).collect();
                        ids.len() == es.len()
                    }),
        ) {
            // Ensure no overlap between active and terminal remote IDs.
            let active_ids: HashSet<_> = active.iter().map(|(r, _)| r).collect();
            let terminal_ids: HashSet<_> = terminal.iter().map(|(r, _)| r).collect();
            prop_assume!(active_ids.is_disjoint(&terminal_ids));

            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                for (remote_id, status) in &active {
                    db.put_status(remote_id, status.clone()).await.unwrap();
                }
                for (remote_id, status) in &terminal {
                    db.put_status(remote_id, status.clone()).await.unwrap();
                }

                let in_progress = db.get_all_in_progress().await.unwrap();

                // Should contain exactly the active entries.
                let result_ids: HashSet<_> =
                    in_progress.iter().map(|(r, _)| r).collect();
                let expected_ids: HashSet<_> =
                    active.iter().map(|(r, _)| r).collect();
                prop_assert_eq!(result_ids, expected_ids);

                // Verify statuses match.
                for (remote_id, status) in &in_progress {
                    let expected = active.iter().find(|(r, _)| r == remote_id).unwrap();
                    prop_assert_eq!(status, &expected.1);
                }

                // `list_status` returns every entry, active or terminal, and
                // `in_progress` matches the async `get_all_in_progress`.
                let all: HashSet<_> = db.list_status().unwrap().into_iter().map(|(r, _)| r).collect();
                let expected_all: HashSet<_> =
                    active.iter().chain(terminal.iter()).map(|(r, _)| r.clone()).collect();
                prop_assert_eq!(all, expected_all);

                let sync_active: HashSet<_> = db.in_progress().unwrap().into_iter().map(|(r, _)| r).collect();
                prop_assert_eq!(sync_active, active.iter().map(|(r, _)| r.clone()).collect::<HashSet<_>>());

                Ok(())
            })?;
        }
    }

    #[test]
    fn delete_status_reports_presence() {
        let (db, _dir) = temp_db();
        let id = RemoteProofId(vec![0xaa, 0xbb]);
        Runtime::new().unwrap().block_on(async {
            db.put_status(&id, RemoteProofStatus::Completed)
                .await
                .unwrap();
        });
        // First delete removes it and reports true; the second finds nothing.
        assert!(db.delete_status(&id).unwrap());
        assert!(!db.delete_status(&id).unwrap());
        assert!(db.list_status().unwrap().is_empty());
    }

    /// Status rows carry no height, so `prune_status_before` places each one
    /// through the reverse mapping and takes only those below the cutoff.
    #[test]
    fn prune_status_before_places_rows_through_the_mapping() {
        let (db, _dir) = temp_db();
        let below = RemoteProofId(vec![1; 8]);
        let above = RemoteProofId(vec![2; 8]);

        Runtime::new().unwrap().block_on(async {
            db.put_remote_proof_id(ProofId::Moho(commitment(4)), below.clone())
                .await
                .unwrap();
            db.put_remote_proof_id(ProofId::Moho(commitment(6)), above.clone())
                .await
                .unwrap();
            db.put_status(&below, RemoteProofStatus::Requested)
                .await
                .unwrap();
            db.put_status(&above, RemoteProofStatus::InProgress)
                .await
                .unwrap();
        });

        let (removed, orphans) = db.prune_status_before(5).unwrap();
        assert_eq!((removed, orphans), (1, 0));
        assert_eq!(db.status(&below).unwrap(), None);
        assert_eq!(
            db.status(&above).unwrap(),
            Some(RemoteProofStatus::InProgress)
        );
    }

    /// A status row with no mapping cannot be placed at any height, so it is
    /// left alone and reported rather than guessed at.
    #[test]
    fn prune_status_before_reports_unplaceable_rows() {
        let (db, _dir) = temp_db();
        let orphan = RemoteProofId(vec![9; 8]);

        Runtime::new().unwrap().block_on(async {
            db.put_status(&orphan, RemoteProofStatus::Requested)
                .await
                .unwrap();
        });

        let (removed, orphans) = db.prune_status_before(u32::MAX).unwrap();
        assert_eq!((removed, orphans), (0, 1));
        assert_eq!(
            db.status(&orphan).unwrap(),
            Some(RemoteProofStatus::Requested)
        );
    }
}
