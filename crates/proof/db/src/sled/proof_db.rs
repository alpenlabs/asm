//! [`ProofDb`] implementation for [`SledProofDb`].

use borsh::BorshDeserialize;
use strata_asm_proof_types::{AsmProof, L1Range, MohoProof};
use strata_identifiers::L1BlockCommitment;

use super::{SledProofDb, decode_moho_key, encode_asm_key, encode_moho_key};
use crate::ProofDb;

impl ProofDb for SledProofDb {
    type Error = sled::Error;

    async fn store_asm_proof(&self, range: L1Range, proof: AsmProof) -> Result<(), Self::Error> {
        let bytes = borsh::to_vec(&proof.0).expect("borsh serialization should not fail");
        self.asm_proofs.insert(encode_asm_key(&range), bytes)?;
        Ok(())
    }

    async fn get_asm_proof(&self, range: L1Range) -> Result<Option<AsmProof>, Self::Error> {
        Ok(self.asm_proofs.get(encode_asm_key(&range))?.map(|v| {
            AsmProof(
                BorshDeserialize::try_from_slice(&v).expect("stored proof should be valid borsh"),
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
        Ok(self.moho_proofs.get(encode_moho_key(&l1ref))?.map(|v| {
            MohoProof(
                BorshDeserialize::try_from_slice(&v).expect("stored proof should be valid borsh"),
            )
        }))
    }

    async fn get_latest_moho_proof(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error> {
        Ok(self.moho_proofs.last()?.map(|(k, v)| {
            let commitment = decode_moho_key(&k);
            let proof = MohoProof(
                BorshDeserialize::try_from_slice(&v).expect("stored proof should be valid borsh"),
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

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prelude::*};
    use strata_identifiers::{Buf32, L1BlockId};
    use tokio::runtime::Runtime;

    use super::*;
    use crate::sled::test_util::*;

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
}
