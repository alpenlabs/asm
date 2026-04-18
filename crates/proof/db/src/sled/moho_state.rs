//! [`MohoStateDb`] implementation backed by sled.

use moho_types::MohoState;
use ssz::{Decode, Encode};
use strata_identifiers::L1BlockCommitment;

use super::encode_moho_key;
use crate::MohoStateDb;

/// Sled-backed store for [`MohoState`] snapshots keyed by [`L1BlockCommitment`].
///
/// Values are SSZ-encoded; keys use the same big-endian height encoding as the
/// proof trees so lexicographic range scans match block-height ordering.
#[derive(Debug, Clone)]
pub struct SledMohoStateDb {
    moho_states: sled::Tree,
}

impl SledMohoStateDb {
    /// Opens the Moho-state tree on an already-open sled database.
    ///
    /// Callers open the [`sled::Db`] themselves so multiple handles — e.g.
    /// [`super::SledProofDb`] — can share the same on-disk directory; sled
    /// does not allow opening the same path twice in a process.
    pub fn open(db: &sled::Db) -> Result<Self, sled::Error> {
        Ok(Self {
            moho_states: db.open_tree("moho_states")?,
        })
    }
}

impl MohoStateDb for SledMohoStateDb {
    type Error = sled::Error;

    async fn store_moho_state(
        &self,
        l1ref: L1BlockCommitment,
        state: MohoState,
    ) -> Result<(), Self::Error> {
        self.moho_states
            .insert(encode_moho_key(&l1ref), state.as_ssz_bytes())?;
        Ok(())
    }

    async fn get_moho_state(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoState>, Self::Error> {
        Ok(self
            .moho_states
            .get(encode_moho_key(&l1ref))?
            .map(|v| MohoState::from_ssz_bytes(&v).expect("stored state should be valid SSZ")))
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        let upper: &[u8] = &before_height.to_be_bytes();

        for entry in self.moho_states.range(..upper) {
            let (key, _) = entry?;
            self.moho_states.remove(&key)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use moho_types::{ExportState, InnerStateCommitment, MohoState};
    use proptest::{collection::vec, prelude::*};
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
    use strata_predicate::PredicateKey;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::sled::test_util::*;

    /// Creates an isolated [`SledMohoStateDb`] backed by a temporary directory.
    fn temp_moho_db() -> (SledMohoStateDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = sled::open(dir.path()).expect("failed to open sled db");
        let moho_db = SledMohoStateDb::open(&db).expect("failed to open moho state tree");
        (moho_db, dir)
    }

    /// Generates an arbitrary [`MohoState`].
    fn arb_moho_state() -> impl Strategy<Value = MohoState> {
        any::<[u8; 32]>().prop_map(|inner| {
            MohoState::new(
                InnerStateCommitment::from(inner),
                PredicateKey::always_accept(),
                ExportState::new(vec![]).unwrap(),
            )
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: a stored Moho state can be retrieved with the same commitment key.
        #[test]
        fn moho_state_roundtrip(
            commitment in arb_l1_block_commitment(),
            state in arb_moho_state(),
        ) {
            let (db, _dir) = temp_moho_db();

            Runtime::new().unwrap().block_on(async {
                db.store_moho_state(commitment, state.clone()).await.unwrap();

                let retrieved = db.get_moho_state(commitment).await.unwrap();

                prop_assert_eq!(Some(state), retrieved);

                Ok(())
            })?;
        }

        /// Property: querying a commitment that was never stored returns `None`.
        #[test]
        fn get_missing_moho_state_returns_none(
            commitment in arb_l1_block_commitment(),
        ) {
            let (db, _dir) = temp_moho_db();

            Runtime::new().unwrap().block_on(async {
                let result = db.get_moho_state(commitment).await.unwrap();

                prop_assert_eq!(result, None);

                Ok(())
            })?;
        }

        /// Property: prune removes entries with height < threshold and preserves
        /// those with height >= threshold.
        #[test]
        fn prune_removes_entries_below_threshold(
            threshold in 100u32..499_999_900u32,
            below in vec(
                (1u32..100u32, any::<[u8; 32]>(), arb_moho_state()),
                1..4,
            ),
            above in vec(
                (0u32..100u32, any::<[u8; 32]>(), arb_moho_state()),
                1..4,
            ),
        ) {
            let (db, _dir) = temp_moho_db();

            Runtime::new().unwrap().block_on(async {
                let below_entries: Vec<_> = below.into_iter().map(|(offset, blkid, state)| {
                    let c = L1BlockCommitment::new(
                        threshold - offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (c, state)
                }).collect();

                let above_entries: Vec<_> = above.into_iter().map(|(offset, blkid, state)| {
                    let c = L1BlockCommitment::new(
                        threshold + offset,
                        L1BlockId::from(Buf32::from(blkid)),
                    );
                    (c, state)
                }).collect();

                for (c, state) in &below_entries {
                    db.store_moho_state(*c, state.clone()).await.unwrap();
                }
                for (c, state) in &above_entries {
                    db.store_moho_state(*c, state.clone()).await.unwrap();
                }

                db.prune(threshold).await.unwrap();

                for (c, _) in &below_entries {
                    let result = db.get_moho_state(*c).await.unwrap();
                    prop_assert_eq!(result, None, "state at height {} should be pruned", c.height());
                }
                for (c, state) in &above_entries {
                    let result = db.get_moho_state(*c).await.unwrap();
                    prop_assert_eq!(result, Some(state.clone()), "state at height {} should survive", c.height());
                }

                Ok(())
            })?;
        }
    }
}
