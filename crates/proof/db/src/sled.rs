//! [`ProofDb`] implementation backed by [sled](https://docs.rs/sled).

use std::{fmt, path::Path};

use borsh::BorshDeserialize;
use strata_asm_proof_types::{AsmProof, L1Range, MohoProof, ProofId, RemoteProofId};
use zkaleido::RemoteProofStatus;
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

use crate::{ProofDb, RemoteProofMappingDb, RemoteProofStatusDb};

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

impl From<sled::Error> for RemoteProofMappingError {
    fn from(e: sled::Error) -> Self {
        Self::Db(e)
    }
}

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

impl From<sled::Error> for RemoteProofStatusError {
    fn from(e: sled::Error) -> Self {
        Self::Db(e)
    }
}

/// Sled-backed proof database.
///
/// Uses two sled trees — one for ASM step proofs and one for Moho recursive
/// proofs. Keys are encoded with big-endian heights so that sled's
/// lexicographic ordering matches block-height ordering.
#[derive(Debug, Clone)]
pub struct SledProofDb {
    asm_proofs: sled::Tree,
    moho_proofs: sled::Tree,
    /// Maps `ProofId` (borsh-encoded) → `RemoteProofId` (raw bytes).
    proof_to_remote: sled::Tree,
    /// Maps `RemoteProofId` (raw bytes) → `ProofId` (borsh-encoded).
    remote_to_proof: sled::Tree,
    /// Maps `RemoteProofId` (raw bytes) → `RemoteProofStatus` (borsh-encoded).
    remote_proof_status: sled::Tree,
}

impl SledProofDb {
    /// Opens (or creates) the proof database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        let asm_proofs = db.open_tree("asm_proofs")?;
        let moho_proofs = db.open_tree("moho_proofs")?;
        let proof_to_remote = db.open_tree("proof_to_remote")?;
        let remote_to_proof = db.open_tree("remote_to_proof")?;
        let remote_proof_status = db.open_tree("remote_proof_status")?;
        Ok(Self {
            asm_proofs,
            moho_proofs,
            proof_to_remote,
            remote_to_proof,
            remote_proof_status,
        })
    }
}

// ── Key encoding ──────────────────────────────────────────────────────

/// Encodes an ASM proof key as 72 bytes:
/// `[start_height_be(4)][start_blkid(32)][end_height_be(4)][end_blkid(32)]`
fn encode_asm_key(range: &L1Range) -> [u8; 72] {
    let mut key = [0u8; 72];
    key[0..4].copy_from_slice(&range.start().height().to_be_bytes());
    key[4..36].copy_from_slice(range.start().blkid().as_ref());
    key[36..40].copy_from_slice(&range.end().height().to_be_bytes());
    key[40..72].copy_from_slice(range.end().blkid().as_ref());
    key
}

/// Encodes a Moho proof key as 36 bytes:
/// `[height_be(4)][blkid(32)]`
fn encode_moho_key(l1ref: &L1BlockCommitment) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[0..4].copy_from_slice(&l1ref.height().to_be_bytes());
    key[4..36].copy_from_slice(l1ref.blkid().as_ref());
    key
}

/// Decodes a Moho proof key back into an [`L1BlockCommitment`].
fn decode_moho_key(key: &[u8]) -> L1BlockCommitment {
    let height = u32::from_be_bytes(key[0..4].try_into().expect("key is at least 4 bytes"));
    let blkid: [u8; 32] = key[4..36].try_into().expect("key is at least 36 bytes");
    L1BlockCommitment::new(height, L1BlockId::from(Buf32::from(blkid)))
}

impl ProofDb for SledProofDb {
    type Error = sled::Error;

    async fn store_asm_proof(&self, range: L1Range, proof: AsmProof) -> Result<(), Self::Error> {
        let bytes = borsh::to_vec(&proof.0).expect("borsh serialization should not fail");
        self.asm_proofs.insert(encode_asm_key(&range), bytes)?;
        Ok(())
    }

    async fn get_asm_proof(&self, range: L1Range) -> Result<Option<AsmProof>, Self::Error> {
        Ok(self
            .asm_proofs
            .get(encode_asm_key(&range))?
            .map(|v| {
                AsmProof(
                    BorshDeserialize::try_from_slice(&v)
                        .expect("stored proof should be valid borsh"),
                )
            }))
    }

    async fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> Result<(), Self::Error> {
        let bytes = borsh::to_vec(&proof.0).expect("borsh serialization should not fail");
        self.moho_proofs.insert(encode_moho_key(&l1ref), bytes)?;
        Ok(())
    }

    async fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoProof>, Self::Error> {
        Ok(self
            .moho_proofs
            .get(encode_moho_key(&l1ref))?
            .map(|v| {
                MohoProof(
                    BorshDeserialize::try_from_slice(&v)
                        .expect("stored proof should be valid borsh"),
                )
            }))
    }

    async fn get_latest_moho_proof(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error> {
        Ok(self.moho_proofs.last()?.map(|(k, v)| {
            let commitment = decode_moho_key(&k);
            let proof = MohoProof(
                BorshDeserialize::try_from_slice(&v)
                    .expect("stored proof should be valid borsh"),
            );
            (commitment, proof)
        }))
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        let upper: &[u8] = &before_height.to_be_bytes();

        // Remove all moho proofs with height < before_height.
        for entry in self.moho_proofs.range(..upper) {
            let (key, _) = entry?;
            self.moho_proofs.remove(&key)?;
        }

        // Remove all ASM proofs with start_height < before_height.
        for entry in self.asm_proofs.range(..upper) {
            let (key, _) = entry?;
            self.asm_proofs.remove(&key)?;
        }

        Ok(())
    }
}

impl RemoteProofMappingDb for SledProofDb {
    type Error = RemoteProofMappingError;

    async fn get_remote_proof_id(
        &self,
        id: ProofId,
    ) -> Result<Option<RemoteProofId>, Self::Error> {
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
        Ok(self
            .remote_to_proof
            .get(&remote_id.0)?
            .map(|v| {
                BorshDeserialize::try_from_slice(&v)
                    .expect("stored ProofId should be valid borsh")
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

impl RemoteProofStatusDb for SledProofDb {
    type Error = RemoteProofStatusError;

    async fn put_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        if self.remote_proof_status.contains_key(&remote_id.0)? {
            return Err(RemoteProofStatusError::AlreadyExists(remote_id.clone()));
        }
        let bytes = borsh::to_vec(&status).expect("borsh serialization should not fail");
        self.remote_proof_status.insert(&remote_id.0, bytes)?;
        Ok(())
    }

    async fn update_status(
        &self,
        remote_id: &RemoteProofId,
        status: RemoteProofStatus,
    ) -> Result<(), Self::Error> {
        if !self.remote_proof_status.contains_key(&remote_id.0)? {
            return Err(RemoteProofStatusError::NotFound(remote_id.clone()));
        }
        let bytes = borsh::to_vec(&status).expect("borsh serialization should not fail");
        self.remote_proof_status.insert(&remote_id.0, bytes)?;
        Ok(())
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
            if matches!(status, RemoteProofStatus::Requested | RemoteProofStatus::InProgress) {
                results.push((RemoteProofId(k.to_vec()), status));
            }
        }
        Ok(results)
    }

    async fn remove(
        &self,
        remote_id: &RemoteProofId,
    ) -> Result<(), Self::Error> {
        self.remote_proof_status.remove(&remote_id.0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};
    use strata_identifiers::{Buf32, L1BlockId};
    use tokio::runtime::Runtime;
    use zkaleido::{Proof, ProofMetadata, ProofReceipt, ProofReceiptWithMetadata, PublicValues, ZkVm};

    use super::*;

    /// Generates an arbitrary L1BlockCommitment.
    /// Heights must be < 500_000_000 (bitcoin LOCK_TIME_THRESHOLD).
    fn arb_l1_block_commitment() -> impl Strategy<Value = L1BlockCommitment> {
        (0u32..500_000_000u32, any::<[u8; 32]>())
            .prop_map(|(h, blkid)| L1BlockCommitment::new(h, L1BlockId::from(Buf32::from(blkid))))
    }

    /// Generates an arbitrary L1Range (end height >= start height).
    fn arb_l1_range() -> impl Strategy<Value = L1Range> {
        (arb_l1_block_commitment(), arb_l1_block_commitment())
            .prop_filter_map("end height must be >= start height", |(a, b)| {
                L1Range::new(a, b)
            })
    }

    fn arb_proof_receipt_with_metadata() -> impl Strategy<Value = ProofReceiptWithMetadata> {
        (vec(any::<u8>(), 0..512), vec(any::<u8>(), 0..512)).prop_map(
            |(proof_bytes, pv_bytes)| {
                let receipt =
                    ProofReceipt::new(Proof::new(proof_bytes), PublicValues::new(pv_bytes));
                let metadata = ProofMetadata::new(ZkVm::Native, "test");
                ProofReceiptWithMetadata::new(receipt, metadata)
            },
        )
    }

    fn arb_asm_proof() -> impl Strategy<Value = AsmProof> {
        arb_proof_receipt_with_metadata().prop_map(AsmProof)
    }

    fn arb_moho_proof() -> impl Strategy<Value = MohoProof> {
        arb_proof_receipt_with_metadata().prop_map(MohoProof)
    }

    /// Creates an isolated [`SledProofDb`] backed by a temporary directory.
    fn temp_db() -> (SledProofDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = SledProofDb::open(dir.path()).expect("failed to open sled db");
        (db, dir)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: any ASM proof stored can be retrieved with the same range key.
        #[test]
        fn asm_proof_roundtrip(
            range in arb_l1_range(),
            proof in arb_asm_proof(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.store_asm_proof(range, proof.clone()).await.unwrap();

                let retrieved = db.get_asm_proof(range).await.unwrap();

                prop_assert_eq!(Some(proof), retrieved);

                Ok(())
            })?;
        }

        /// Property: any Moho proof stored can be retrieved with the same commitment key.
        #[test]
        fn moho_proof_roundtrip(
            commitment in arb_l1_block_commitment(),
            proof in arb_moho_proof(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.store_moho_proof(commitment, proof.clone()).await.unwrap();

                let retrieved = db.get_moho_proof(commitment).await.unwrap();

                prop_assert_eq!(Some(proof), retrieved);

                Ok(())
            })?;
        }
    }

    #[test]
    fn get_nonexistent_asm_proof_returns_none() {
        let (db, _dir) = temp_db();

        Runtime::new().unwrap().block_on(async {
            let commitment =
                L1BlockCommitment::new(999_999, L1BlockId::from(Buf32::from([0xffu8; 32])));
            let range = L1Range::single(commitment);

            let result = db.get_asm_proof(range).await.unwrap();
            assert_eq!(result, None);
        });
    }

    #[test]
    fn get_nonexistent_moho_proof_returns_none() {
        let (db, _dir) = temp_db();

        Runtime::new().unwrap().block_on(async {
            let commitment =
                L1BlockCommitment::new(999_998, L1BlockId::from(Buf32::from([0xfeu8; 32])));

            let result = db.get_moho_proof(commitment).await.unwrap();
            assert_eq!(result, None);
        });
    }

    #[test]
    fn get_latest_moho_proof_returns_none_when_empty() {
        let (db, _dir) = temp_db();

        Runtime::new().unwrap().block_on(async {
            let result = db.get_latest_moho_proof().await.unwrap();
            assert_eq!(result, None);
        });
    }

    /// Generates a Vec of (L1BlockCommitment, MohoProof) pairs.
    fn arb_moho_entries() -> impl Strategy<Value = Vec<(L1BlockCommitment, MohoProof)>> {
        vec((arb_l1_block_commitment(), arb_moho_proof()), 2..10)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Property: after storing multiple Moho proofs, get_latest returns the one
        /// with the highest height.
        #[test]
        fn get_latest_moho_proof_returns_highest(entries in arb_moho_entries()) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                for (commitment, proof) in &entries {
                    db.store_moho_proof(*commitment, proof.clone()).await.unwrap();
                }

                let (latest_commitment, latest_proof) = db
                    .get_latest_moho_proof()
                    .await
                    .unwrap()
                    .expect("should have proofs after storing");

                // Find the entry with the max key (height, then blkid) to match
                // the big-endian lexicographic ordering.
                let expected = entries
                    .iter()
                    .max_by_key(|(c, _)| (c.height(), *c.blkid().as_ref()))
                    .unwrap();

                prop_assert_eq!(latest_commitment.height(), expected.0.height());
                prop_assert_eq!(latest_proof, expected.1.clone());

                Ok(())
            })?;
        }

        /// Property: prune removes entries with height < threshold and preserves
        /// those with height >= threshold, in both the ASM and Moho subspaces.
        #[test]
        fn prune_removes_entries_below_threshold(
            threshold in 100u32..499_999_900u32,
            below_moho in vec(
                (1u32..100u32, any::<[u8; 32]>(), arb_moho_proof()),
                1..4,
            ),
            above_moho in vec(
                (0u32..100u32, any::<[u8; 32]>(), arb_moho_proof()),
                1..4,
            ),
            below_asm in vec(
                (1u32..100u32, any::<[u8; 32]>(), arb_asm_proof()),
                1..4,
            ),
            above_asm in vec(
                (0u32..100u32, any::<[u8; 32]>(), arb_asm_proof()),
                1..4,
            ),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                // Store Moho proofs below the threshold.
                let below_moho_entries: Vec<_> = below_moho.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold - offset,
                        L1BlockId::from(Buf32::from(blkid)));
                    (c, proof)
                }).collect();

                // Store Moho proofs at or above the threshold.
                let above_moho_entries: Vec<_> = above_moho.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold + offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (c, proof)
                }).collect();

                for (c, proof) in &below_moho_entries {
                    db.store_moho_proof(*c, proof.clone()).await.unwrap();
                }
                for (c, proof) in &above_moho_entries {
                    db.store_moho_proof(*c, proof.clone()).await.unwrap();
                }

                // Store ASM proofs below the threshold (single-block ranges).
                let below_asm_entries: Vec<_> = below_asm.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold - offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (L1Range::single(c), proof)
                }).collect();

                // Store ASM proofs at or above the threshold.
                let above_asm_entries: Vec<_> = above_asm.into_iter().map(|(offset, blkid, proof)| {
                    let c = L1BlockCommitment::new(
                        threshold + offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (L1Range::single(c), proof)
                }).collect();

                for (range, proof) in &below_asm_entries {
                    db.store_asm_proof(*range, proof.clone()).await.unwrap();
                }
                for (range, proof) in &above_asm_entries {
                    db.store_asm_proof(*range, proof.clone()).await.unwrap();
                }

                // Prune at threshold.
                db.prune(threshold).await.unwrap();

                // Moho entries below threshold should be gone.
                for (c, _) in &below_moho_entries {
                    let result = db.get_moho_proof(*c).await.unwrap();
                    prop_assert_eq!(result, None, "moho at height {} should be pruned", c.height());
                }
                // Moho entries at or above threshold should survive.
                for (c, proof) in &above_moho_entries {
                    let result = db.get_moho_proof(*c).await.unwrap();
                    prop_assert_eq!(result, Some(proof.clone()), "moho at height {} should survive", c.height());
                }

                // ASM entries below threshold should be gone.
                for (range, _) in &below_asm_entries {
                    let result = db.get_asm_proof(*range).await.unwrap();
                    prop_assert_eq!(result, None, "asm at height {} should be pruned", range.start().height());
                }
                // ASM entries at or above threshold should survive.
                for (range, proof) in &above_asm_entries {
                    let result = db.get_asm_proof(*range).await.unwrap();
                    prop_assert_eq!(result, Some(proof.clone()), "asm at height {} should survive", range.start().height());
                }

                Ok(())
            })?;
        }
    }

    // ── RemoteProofMappingDb tests ───────────────────────────────────

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
                        let ids: std::collections::HashSet<_> = es.iter().map(|(p, _)| p).collect();
                        ids.len() == es.len()
                    })
                .prop_filter("remote IDs must be unique",
                    |es| {
                        let ids: std::collections::HashSet<_> = es.iter().map(|(_, r)| r).collect();
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

    // ── RemoteProofStatusDb tests ────────────────────────────────────

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
                        let ids: std::collections::HashSet<_> = es.iter().map(|(r, _)| r).collect();
                        ids.len() == es.len()
                    }),
            terminal in vec((arb_remote_proof_id(), arb_terminal_status()), 1..5)
                .prop_filter("unique remote IDs",
                    |es| {
                        let ids: std::collections::HashSet<_> = es.iter().map(|(r, _)| r).collect();
                        ids.len() == es.len()
                    }),
        ) {
            // Ensure no overlap between active and terminal remote IDs.
            let active_ids: std::collections::HashSet<_> = active.iter().map(|(r, _)| r).collect();
            let terminal_ids: std::collections::HashSet<_> = terminal.iter().map(|(r, _)| r).collect();
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
                let result_ids: std::collections::HashSet<_> =
                    in_progress.iter().map(|(r, _)| r).collect();
                let expected_ids: std::collections::HashSet<_> =
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
