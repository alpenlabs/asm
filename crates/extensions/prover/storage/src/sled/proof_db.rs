//! [`ProofDb`] implementation for [`SledProofDb`].

use borsh::BorshDeserialize;
use strata_asm_prover_types::{AsmProof, L1Range, MohoProof};
use strata_identifiers::L1BlockCommitment;

use super::{
    PruneCounts, SledProofDb, decode_asm_key, decode_moho_key, encode_asm_key, encode_moho_key,
};
use crate::ProofDb;

/// Synchronous proof accessors.
///
/// The [`ProofDb`] async trait below delegates to these; the worker uses the
/// trait, while offline tooling (the dbtool) drives them directly to stay
/// synchronous. `list_*`/`delete_*` have no async-trait counterpart — they exist
/// only for that tooling.
impl SledProofDb {
    /// Stores an ASM step proof for `range`.
    pub fn store_asm(&self, range: &L1Range, proof: &AsmProof) -> Result<(), sled::Error> {
        let bytes = borsh::to_vec(&proof.0).expect("borsh serialization should not fail");
        self.asm_proofs.insert(encode_asm_key(range), bytes)?;
        Ok(())
    }

    /// Retrieves the ASM step proof for `range`, if one exists.
    pub fn get_asm(&self, range: &L1Range) -> Result<Option<AsmProof>, sled::Error> {
        Ok(self.asm_proofs.get(encode_asm_key(range))?.map(|v| {
            AsmProof(
                BorshDeserialize::try_from_slice(&v).expect("stored proof should be valid borsh"),
            )
        }))
    }

    /// Stores a Moho recursive proof anchored at `l1ref`.
    pub fn store_moho(
        &self,
        l1ref: &L1BlockCommitment,
        proof: &MohoProof,
    ) -> Result<(), sled::Error> {
        let bytes = borsh::to_vec(&proof.0).expect("borsh serialization should not fail");
        self.moho_proofs.insert(encode_moho_key(l1ref), bytes)?;
        Ok(())
    }

    /// Retrieves the Moho proof anchored at `l1ref`, if one exists.
    pub fn get_moho(&self, l1ref: &L1BlockCommitment) -> Result<Option<MohoProof>, sled::Error> {
        Ok(self.moho_proofs.get(encode_moho_key(l1ref))?.map(|v| {
            MohoProof(
                BorshDeserialize::try_from_slice(&v).expect("stored proof should be valid borsh"),
            )
        }))
    }

    /// Returns the highest-height Moho proof and its anchor, or `None` if empty.
    pub fn get_latest_moho(&self) -> Result<Option<(L1BlockCommitment, MohoProof)>, sled::Error> {
        Ok(self.moho_proofs.last()?.map(|(k, v)| {
            let commitment = decode_moho_key(&k);
            let proof = MohoProof(
                BorshDeserialize::try_from_slice(&v).expect("stored proof should be valid borsh"),
            );
            (commitment, proof)
        }))
    }

    /// Removes every trace of the proofs for blocks below `before_height`: the
    /// ASM and Moho proofs themselves, the status rows of the remote jobs that
    /// produced them, and both directions of their id mapping.
    ///
    /// The bookkeeping goes too because a mapping row outliving its proof is
    /// not merely stale: the row records that the proof was submitted, so a
    /// pruned block would still read as submitted with no proof to show for it.
    /// This is the store's own invariant, not the [`ProofDb`] contract — that
    /// trait covers the proof trees alone, and a store holding only those has
    /// nothing else to clear.
    ///
    /// Status rows are cleared before mapping rows, and not the other way
    /// round: a status row carries no height of its own and is placed through
    /// the reverse mapping, so tearing the mapping down first would strand
    /// every status row below the cutoff as an unplaceable orphan. The same
    /// order makes a crash midway harmless — a re-run recomputes the same set
    /// and finishes the job.
    pub fn prune_before(&self, before_height: u32) -> Result<PruneCounts, sled::Error> {
        let upper: &[u8] = &before_height.to_be_bytes();
        let mut counts = PruneCounts::default();

        // Remove all moho proofs with height < before_height.
        for entry in self.moho_proofs.range(..upper) {
            let (key, _) = entry?;
            if self.moho_proofs.remove(&key)?.is_some() {
                counts.moho_proofs += 1;
            }
        }

        // Remove all ASM proofs with start_height < before_height.
        for entry in self.asm_proofs.range(..upper) {
            let (key, _) = entry?;
            if self.asm_proofs.remove(&key)?.is_some() {
                counts.asm_proofs += 1;
            }
        }

        let (statuses, orphan_statuses) = self.prune_status_before(before_height)?;
        counts.statuses = statuses;
        counts.orphan_statuses = orphan_statuses;

        counts.mappings = self.prune_mappings_before(before_height)?;

        Ok(counts)
    }

    /// Lists every stored ASM proof key, in ascending range order.
    ///
    /// Keys decode losslessly via `decode_asm_key`; the (large) proof values
    /// are not read.
    pub fn list_asm(&self) -> Result<Vec<L1Range>, sled::Error> {
        self.asm_proofs
            .iter()
            .keys()
            .map(|key| {
                let key = key?;
                let bytes: &[u8; super::ENCODED_L1_RANGE_SIZE] = key
                    .as_ref()
                    .try_into()
                    .expect("asm proof key is a fixed-size range key");
                Ok(decode_asm_key(bytes))
            })
            .collect()
    }

    /// Lists every stored Moho proof anchor, in ascending height order.
    pub fn list_moho(&self) -> Result<Vec<L1BlockCommitment>, sled::Error> {
        self.moho_proofs
            .iter()
            .keys()
            .map(|key| Ok(decode_moho_key(&key?)))
            .collect()
    }

    /// Removes the ASM proof for `range`, returning whether one was present.
    pub fn delete_asm(&self, range: &L1Range) -> Result<bool, sled::Error> {
        Ok(self.asm_proofs.remove(encode_asm_key(range))?.is_some())
    }

    /// Removes the Moho proof for `l1ref`, returning whether one was present.
    pub fn delete_moho(&self, l1ref: &L1BlockCommitment) -> Result<bool, sled::Error> {
        Ok(self.moho_proofs.remove(encode_moho_key(l1ref))?.is_some())
    }
}

impl ProofDb for SledProofDb {
    type Error = sled::Error;

    async fn store_asm_proof(&self, range: L1Range, proof: AsmProof) -> Result<(), Self::Error> {
        self.store_asm(&range, &proof)
    }

    async fn get_asm_proof(&self, range: L1Range) -> Result<Option<AsmProof>, Self::Error> {
        self.get_asm(&range)
    }

    async fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> Result<(), Self::Error> {
        self.store_moho(&l1ref, &proof)
    }

    async fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoProof>, Self::Error> {
        self.get_moho(&l1ref)
    }

    async fn get_latest_moho_proof(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error> {
        self.get_latest_moho()
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        // Sweeps the mapping and status trees as well, which is more than the
        // trait asks for: this store owns them, so it keeps them consistent
        // with the proofs. The per-tree counts serve the offline tooling that
        // reports them; a caller of the trait only needs the success.
        self.prune_before(before_height).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::{collection::vec, prelude::*};
    use strata_asm_prover_types::{ProofId, RemoteProofId};
    use strata_identifiers::{Buf32, L1BlockId};
    use tokio::runtime::Runtime;
    use zkaleido::RemoteProofStatus;

    use super::*;
    use crate::{RemoteProofMappingDb, RemoteProofStatusDb, sled::test_util::*};

    /// A commitment at `height` with a fixed block id, for the tests that care
    /// about heights rather than identity.
    fn commitment(height: u32) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::new([0; 32])))
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Property: `list_asm` returns every stored range, sorted, and
        /// `delete_asm` removes exactly the targeted range.
        #[test]
        fn list_and_delete_asm(entries in vec((arb_l1_range(), arb_asm_proof()), 1..5)) {
            let (db, _dir) = temp_db();
            for (range, proof) in &entries {
                db.store_asm(range, proof).unwrap();
            }

            // Same range key overwrites, so the stored set is the dedup'd input.
            let expected: BTreeSet<_> = entries.iter().map(|(r, _)| *r).collect();
            let listed = db.list_asm().unwrap();
            prop_assert_eq!(listed.iter().copied().collect::<BTreeSet<_>>(), expected.clone());

            let mut sorted = listed.clone();
            sorted.sort();
            prop_assert_eq!(&listed, &sorted, "list_asm must be ascending");

            for range in &expected {
                prop_assert!(db.delete_asm(range).unwrap());
            }
            prop_assert!(db.list_asm().unwrap().is_empty());
            // Deleting an absent range reports no removal.
            prop_assert!(!db.delete_asm(expected.iter().next().unwrap()).unwrap());
        }

        /// Property: `list_moho` returns every stored anchor, sorted, and
        /// `delete_moho` removes exactly the targeted anchor.
        #[test]
        fn list_and_delete_moho(entries in vec((arb_l1_block_commitment(), arb_moho_proof()), 1..5)) {
            let (db, _dir) = temp_db();
            for (commitment, proof) in &entries {
                db.store_moho(commitment, proof).unwrap();
            }

            let expected: BTreeSet<_> = entries.iter().map(|(c, _)| *c).collect();
            let listed = db.list_moho().unwrap();
            prop_assert_eq!(listed.iter().copied().collect::<BTreeSet<_>>(), expected.clone());

            for commitment in &expected {
                prop_assert!(db.delete_moho(commitment).unwrap());
            }
            prop_assert!(db.list_moho().unwrap().is_empty());
            prop_assert!(!db.delete_moho(expected.iter().next().unwrap()).unwrap());
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

    /// One prune clears every tree: the proofs and the remote-prover
    /// bookkeeping that would otherwise mark a pruned block as already
    /// submitted and keep it from ever being proven again.
    #[test]
    fn prune_before_sweeps_bookkeeping_with_the_proofs() {
        let (db, _dir) = temp_db();
        let (low, high) = (commitment(4), commitment(6));
        let (low_remote, high_remote) = (RemoteProofId(vec![1; 8]), RemoteProofId(vec![2; 8]));

        Runtime::new().unwrap().block_on(async {
            for block in [low, high] {
                db.store_moho_proof(block, MohoProof(fixed_proof_receipt()))
                    .await
                    .unwrap();
                db.store_asm_proof(L1Range::single(block), AsmProof(fixed_proof_receipt()))
                    .await
                    .unwrap();
            }
            for (block, remote) in [(low, &low_remote), (high, &high_remote)] {
                db.put_remote_proof_id(ProofId::Moho(block), remote.clone())
                    .await
                    .unwrap();
                db.put_status(remote, RemoteProofStatus::Requested)
                    .await
                    .unwrap();
            }
        });

        let counts = db.prune_before(5).unwrap();
        assert_eq!(counts.asm_proofs, 1);
        assert_eq!(counts.moho_proofs, 1);
        assert_eq!(counts.statuses, 1);
        // Forward and reverse row for the one pruned proof id.
        assert_eq!(counts.mappings, 2);
        assert_eq!(counts.orphan_statuses, 0);

        // Nothing below the cutoff survives in any tree.
        assert!(db.get_moho(&low).unwrap().is_none());
        assert!(db.get_asm(&L1Range::single(low)).unwrap().is_none());
        assert!(db.get_remote(ProofId::Moho(low)).unwrap().is_none());
        assert!(db.status(&low_remote).unwrap().is_none());

        // Everything at or above it is untouched.
        assert!(db.get_moho(&high).unwrap().is_some());
        assert!(db.get_asm(&L1Range::single(high)).unwrap().is_some());
        assert!(db.get_remote(ProofId::Moho(high)).unwrap().is_some());
        assert!(db.status(&high_remote).unwrap().is_some());
    }
}
