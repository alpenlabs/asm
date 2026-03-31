//! [`RemoteProofStatusDb`] implementation for [`SledProofDb`].

use std::{error::Error, fmt};

use borsh::BorshDeserialize;
use strata_asm_proof_types::RemoteProofId;
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
        Ok(self.remote_proof_status.get(&remote_id.0)?.map(|v| {
            BorshDeserialize::try_from_slice(&v)
                .expect("stored RemoteProofStatus should be valid borsh")
        }))
    }

    async fn get_all_in_progress(
        &self,
    ) -> Result<Vec<(RemoteProofId, RemoteProofStatus)>, Self::Error> {
        let mut results = Vec::new();
        for entry in self.remote_proof_status.iter() {
            let (k, v) = entry?;
            let status: RemoteProofStatus = BorshDeserialize::try_from_slice(&v)
                .expect("stored RemoteProofStatus should be valid borsh");
            if matches!(
                status,
                RemoteProofStatus::Requested | RemoteProofStatus::InProgress
            ) {
                results.push((RemoteProofId(k.to_vec()), status));
            }
        }
        Ok(results)
    }

    async fn remove(&self, remote_id: &RemoteProofId) -> Result<(), Self::Error> {
        self.remote_proof_status.remove(&remote_id.0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::{collection::vec, prelude::*};
    use tokio::runtime::Runtime;

    use super::*;
    use crate::sled::test_util::*;

    /// Generates an arbitrary [`RemoteProofId`].
    fn arb_remote_proof_id() -> impl Strategy<Value = RemoteProofId> {
        vec(any::<u8>(), 1..64).prop_map(RemoteProofId)
    }

    /// Generates an arbitrary [`RemoteProofStatus`].
    fn arb_remote_proof_status() -> impl Strategy<Value = RemoteProofStatus> {
        prop_oneof![
            Just(RemoteProofStatus::Requested),
            Just(RemoteProofStatus::InProgress),
            Just(RemoteProofStatus::Completed),
            ".*".prop_map(RemoteProofStatus::Failed),
            Just(RemoteProofStatus::Unknown),
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
            ".*".prop_map(RemoteProofStatus::Failed),
            Just(RemoteProofStatus::Unknown),
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

                Ok(())
            })?;
        }
    }
}
