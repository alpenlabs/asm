//! [`RemoteProofMappingDb`] implementation for [`SledProofDb`].
//!
//! Two trees back the mapping, and they are not exact inverses of each other.
//!
//! `proof_to_remote` records that a proof was submitted and which remote job
//! took it. One entry per proof, replaced when the proof is submitted again.
//!
//! `remote_to_proof` records every remote job a proof has had, one entry per
//! job. Entries stay after `proof_to_remote` stops naming them, so a reply
//! from an older job still resolves back to its proof. Nothing removes them:
//! they are keyed by remote id, so finding the entries for one proof would
//! mean scanning the whole tree.

use std::{error::Error, fmt};

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
/// The read half of [`RemoteProofMappingDb`] delegates to these;
/// `list_mappings` and `clear_remote_submission` have no async-trait
/// counterpart and exist only for that tooling.
impl SledProofDb {
    /// Returns the remote proof ID mapped to local `id`, if any.
    pub fn get_remote(&self, id: ProofId) -> Result<Option<RemoteProofId>, sled::Error> {
        let key = borsh::to_vec(&id).expect("borsh serialization should not fail");
        Ok(self
            .proof_to_remote
            .get(key)?
            .map(|v| RemoteProofId(v.to_vec())))
    }

    /// Returns the local proof ID mapped to `remote_id`, if any.
    pub fn get_local(&self, remote_id: &RemoteProofId) -> Result<Option<ProofId>, sled::Error> {
        Ok(self.remote_to_proof.get(&remote_id.0)?.map(|v| {
            BorshDeserialize::try_from_slice(&v).expect("stored ProofId should be valid borsh")
        }))
    }

    /// Lists every stored mapping as `(local, remote)` pairs.
    ///
    /// Iterates `remote_to_proof`, which holds an entry per remote job.
    /// `proof_to_remote` keeps only each proof's latest remote id, so
    /// enumerating that instead would drop the earlier ones.
    pub fn list_mappings(&self) -> Result<Vec<(ProofId, RemoteProofId)>, sled::Error> {
        self.remote_to_proof
            .iter()
            .map(|entry| {
                let (remote_bytes, local_bytes) = entry?;
                let local: ProofId = BorshDeserialize::try_from_slice(&local_bytes)
                    .expect("stored ProofId should be valid borsh");
                Ok((local, RemoteProofId(remote_bytes.to_vec())))
            })
            .collect()
    }

    /// Forgets that `id` was submitted to the remote prover, freeing it to be
    /// submitted again. Returns whether a submission was on record.
    ///
    /// The remote jobs it has already had stay resolvable; see the module
    /// docs for the split between the two trees.
    pub fn clear_remote_submission(&self, id: ProofId) -> Result<bool, sled::Error> {
        let proof_key = borsh::to_vec(&id).expect("borsh serialization should not fail");
        Ok(self.proof_to_remote.remove(proof_key)?.is_some())
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
            // Same proof ID: fall through and rewrite both trees. The
            // `proof_to_remote` entry may have been cleared on its own, and
            // this is what restores it.
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
    use strata_asm_prover_types::ProofId;
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use tokio::runtime::Runtime;

    use super::*;
    use crate::sled::test_util::*;

    /// A commitment at `height` with a fixed block id, for the tests that care
    /// about heights rather than identity.
    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::new([0; 32])))
    }

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
        /// (resubmission). The proof resolves to the latest remote ID, and
        /// every remote ID it has used still resolves back to it.
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

                // Both remote IDs still resolve to the same proof ID.
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

    /// Clearing a submission leaves `remote_to_proof` alone, so which remote
    /// jobs a proof has had stays resolvable.
    #[test]
    fn clear_remote_submission_keeps_remote_ids_resolvable() {
        let (db, _dir) = temp_db();
        let id = ProofId::Moho(commitment(10));
        let first = RemoteProofId(vec![1; 8]);
        let second = RemoteProofId(vec![2; 8]);

        Runtime::new().unwrap().block_on(async {
            db.put_remote_proof_id(id, first.clone()).await.unwrap();
            db.put_remote_proof_id(id, second.clone()).await.unwrap();
        });

        assert!(db.clear_remote_submission(id).unwrap());
        assert_eq!(db.get_remote(id).unwrap(), None);
        assert_eq!(db.get_local(&first).unwrap(), Some(id));
        assert_eq!(db.get_local(&second).unwrap(), Some(id));

        // A second clear finds no submission on record.
        assert!(!db.clear_remote_submission(id).unwrap());
    }

    /// Re-putting an identical pair restores a cleared submission.
    ///
    /// Remote ids are expected to differ between submissions, but storage does
    /// not get to assume it. A repeat arrives with its `remote_to_proof` entry
    /// already there, which must not read as "nothing to do": the proof would
    /// stay unmapped and resubmit on every tick.
    #[test]
    fn put_restores_a_cleared_submission() {
        let (db, _dir) = temp_db();
        let id = ProofId::Moho(commitment(10));
        let remote = RemoteProofId(vec![7; 8]);

        Runtime::new().unwrap().block_on(async {
            db.put_remote_proof_id(id, remote.clone()).await.unwrap();
            db.clear_remote_submission(id).unwrap();
            assert_eq!(db.get_remote(id).unwrap(), None);

            // The backend hands back an id it already used for this proof.
            db.put_remote_proof_id(id, remote.clone()).await.unwrap();
        });

        assert_eq!(db.get_remote(id).unwrap(), Some(remote));
    }

    /// Clearing a submission touches only the proof it names.
    #[test]
    fn clear_remote_submission_leaves_other_proofs_alone() {
        let (db, _dir) = temp_db();
        let target = ProofId::Moho(commitment(10));
        let other = ProofId::Moho(commitment(11));
        let target_remote = RemoteProofId(vec![1; 8]);
        let other_remote = RemoteProofId(vec![2; 8]);

        Runtime::new().unwrap().block_on(async {
            db.put_remote_proof_id(target, target_remote).await.unwrap();
            db.put_remote_proof_id(other, other_remote.clone())
                .await
                .unwrap();
        });

        db.clear_remote_submission(target).unwrap();
        assert_eq!(db.get_remote(other).unwrap(), Some(other_remote));
    }
}
