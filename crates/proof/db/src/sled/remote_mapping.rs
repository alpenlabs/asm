//! [`RemoteProofMappingDb`] implementation for [`SledProofDb`].

use std::fmt;

use borsh::BorshDeserialize;
use strata_asm_proof_types::{ProofId, RemoteProofId};

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

impl std::error::Error for RemoteProofMappingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
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

impl RemoteProofMappingDb for SledProofDb {
    type Error = RemoteProofMappingError;

    async fn get_remote_proof_id(&self, id: ProofId) -> Result<Option<RemoteProofId>, Self::Error> {
        let key = borsh::to_vec(&id).expect("borsh serialization should not fail");
        Ok(self
            .proof_to_remote
            .get(key)?
            .map(|v| RemoteProofId(v.to_vec())))
    }

    async fn get_proof_id(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<Option<ProofId>, Self::Error> {
        Ok(self.remote_to_proof.get(&remote_id.0)?.map(|v| {
            BorshDeserialize::try_from_slice(&v).expect("stored ProofId should be valid borsh")
        }))
    }

    async fn put_remote_proof_id(
        &self,
        id: ProofId,
        remote_id: RemoteProofId,
    ) -> Result<(), Self::Error> {
        let proof_key = borsh::to_vec(&id).expect("borsh serialization should not fail");

        // Check if this remote ID is already mapped to a different proof ID.
        if let Some(existing_bytes) = self.remote_to_proof.get(&remote_id.0)? {
            let existing: ProofId = BorshDeserialize::try_from_slice(&existing_bytes)
                .expect("stored ProofId should be valid borsh");
            if existing != id {
                return Err(RemoteProofMappingError::DuplicateRemoteId {
                    remote_id,
                    existing,
                    attempted: id,
                });
            }
            // Same proof ID → same mapping, nothing to do.
            return Ok(());
        }

        self.proof_to_remote
            .insert(proof_key.as_slice(), remote_id.0.as_slice())?;
        self.remote_to_proof
            .insert(remote_id.0.as_slice(), proof_key.as_slice())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::{collection::vec, prelude::*};
    use strata_asm_proof_types::ProofId;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::sled::test_util::*;

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
    }
}
