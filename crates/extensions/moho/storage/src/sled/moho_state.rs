//! [`MohoStateDb`] implementation backed by sled.

use moho_types::MohoState;
use ssz::{Decode, Encode};
use strata_identifiers::L1BlockCommitment;

use super::{decode_moho_key, encode_moho_key};
use crate::MohoStateDb;

/// Sled-backed store for [`MohoState`] snapshots keyed by [`L1BlockCommitment`].
///
/// Values are SSZ-encoded; keys use big-endian height encoding so lexicographic
/// range scans match block-height ordering.
#[derive(Debug, Clone)]
pub struct SledMohoStateDb {
    moho_states: sled::Tree,
}

impl SledMohoStateDb {
    /// Opens the Moho-state tree on an already-open sled database.
    ///
    /// Callers open the [`sled::Db`] themselves so multiple handles can share
    /// the same on-disk directory; sled does not allow opening the same path
    /// twice in a process.
    pub fn open(db: &sled::Db) -> Result<Self, sled::Error> {
        Ok(Self {
            moho_states: db.open_tree("moho_states")?,
        })
    }

    /// Synchronous variant of [`MohoStateDb::store_moho_state`]. The Moho worker
    /// interacts with storage through synchronous traits (`MohoStateStore`), and
    /// it runs as an async service where a nested `Handle::block_on` would panic,
    /// so the worker calls these sync methods directly rather than the async
    /// trait below.
    pub fn store(&self, l1ref: L1BlockCommitment, state: MohoState) -> Result<(), sled::Error> {
        self.moho_states
            .insert(encode_moho_key(&l1ref), state.as_ssz_bytes())?;
        Ok(())
    }

    /// Synchronous variant of [`MohoStateDb::get_moho_state`]. See [`Self::store`].
    pub fn get(&self, l1ref: L1BlockCommitment) -> Result<Option<MohoState>, sled::Error> {
        Ok(self
            .moho_states
            .get(encode_moho_key(&l1ref))?
            .map(|v| MohoState::from_ssz_bytes(&v).expect("stored state should be valid SSZ")))
    }

    /// Returns the highest-height stored Moho state and the block it is anchored
    /// to, or `None` when the store is empty.
    ///
    /// Keys are big-endian `[height‖blkid]`, so the last entry is the
    /// highest-height one (ties broken by block id). The Moho worker uses this to
    /// resume from its latest committed state across restarts.
    pub fn get_latest(&self) -> Result<Option<(L1BlockCommitment, MohoState)>, sled::Error> {
        let Some((key, value)) = self.moho_states.last()? else {
            return Ok(None);
        };
        let commitment = decode_moho_key(&key);
        let state = MohoState::from_ssz_bytes(&value).expect("stored state should be valid SSZ");
        Ok(Some((commitment, state)))
    }

    /// Synchronous variant of [`MohoStateDb::prune`]. See [`Self::store`].
    pub fn prune_before(&self, before_height: u32) -> Result<(), sled::Error> {
        let upper: &[u8] = &before_height.to_be_bytes();

        for entry in self.moho_states.range(..upper) {
            let (key, _) = entry?;
            self.moho_states.remove(&key)?;
        }

        Ok(())
    }

    /// Removes every entry with height strictly above `after_height`, keeping the
    /// height itself.
    ///
    /// Rolls the store back to a known-good height; the worker only ever prunes
    /// old state from below, so this exists for offline maintenance tooling.
    pub fn prune_after(&self, after_height: u32) -> Result<(), sled::Error> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        for entry in self.moho_states.range(lower..) {
            let (key, _) = entry?;
            self.moho_states.remove(&key)?;
        }
        Ok(())
    }

    /// Removes the Moho state for `l1ref`, returning whether one was present.
    ///
    /// For inspection tooling; the worker never deletes individual states.
    pub fn delete(&self, l1ref: &L1BlockCommitment) -> Result<bool, sled::Error> {
        Ok(self.moho_states.remove(encode_moho_key(l1ref))?.is_some())
    }

    /// Returns every stored Moho-state key, in ascending height order.
    ///
    /// For inspection tooling: keys are decoded from the tree without reading
    /// the (large) values.
    pub fn list(&self) -> Result<Vec<L1BlockCommitment>, sled::Error> {
        self.moho_states
            .iter()
            .keys()
            .map(|key| Ok(decode_moho_key(&key?)))
            .collect()
    }
}

impl MohoStateDb for SledMohoStateDb {
    type Error = sled::Error;

    async fn store_moho_state(
        &self,
        l1ref: L1BlockCommitment,
        state: MohoState,
    ) -> Result<(), Self::Error> {
        self.store(l1ref, state)
    }

    async fn get_moho_state(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoState>, Self::Error> {
        self.get(l1ref)
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        self.prune_before(before_height)
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

    fn moho_state(inner: u8) -> MohoState {
        MohoState::new(
            InnerStateCommitment::from([inner; 32]),
            PredicateKey::always_accept(),
            ExportState::new(vec![]).unwrap(),
        )
    }

    #[test]
    fn get_latest_on_empty_returns_none() {
        let (db, _dir) = temp_moho_db();
        assert!(db.get_latest().unwrap().is_none());
    }

    #[test]
    fn get_latest_returns_highest_height() {
        let (db, _dir) = temp_moho_db();
        let low = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let high = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x22; 32])));

        // Store out of height order to prove ordering comes from the key, not
        // insertion order.
        db.store(high, moho_state(0xbb)).unwrap();
        db.store(low, moho_state(0xaa)).unwrap();

        let (blk, state) = db.get_latest().unwrap().unwrap();
        assert_eq!(blk, high);
        assert_eq!(state, moho_state(0xbb));
    }

    #[test]
    fn list_returns_keys_in_height_order() {
        let (db, _dir) = temp_moho_db();
        let low = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let high = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x22; 32])));

        assert!(db.list().unwrap().is_empty());
        db.store(high, moho_state(0xbb)).unwrap();
        db.store(low, moho_state(0xaa)).unwrap();

        // Keys come back in ascending height order regardless of insertion order.
        assert_eq!(db.list().unwrap(), vec![low, high]);
    }

    #[test]
    fn delete_removes_only_the_targeted_key() {
        let (db, _dir) = temp_moho_db();
        let a = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let b = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x22; 32])));
        db.store(a, moho_state(0xaa)).unwrap();
        db.store(b, moho_state(0xbb)).unwrap();

        assert!(db.delete(&a).unwrap());
        assert!(db.get(a).unwrap().is_none());
        assert!(db.get(b).unwrap().is_some());
        // Deleting an absent key reports no removal.
        assert!(!db.delete(&a).unwrap());
    }

    #[test]
    fn prune_after_removes_entries_above_height() {
        let (db, _dir) = temp_moho_db();
        let keep = L1BlockCommitment::new(10, L1BlockId::from(Buf32::from([0x11; 32])));
        let boundary = L1BlockCommitment::new(20, L1BlockId::from(Buf32::from([0x22; 32])));
        let drop = L1BlockCommitment::new(21, L1BlockId::from(Buf32::from([0x33; 32])));
        db.store(keep, moho_state(0xaa)).unwrap();
        db.store(boundary, moho_state(0xbb)).unwrap();
        db.store(drop, moho_state(0xcc)).unwrap();

        db.prune_after(20).unwrap();

        // The boundary height is kept; strictly-higher entries are removed.
        assert!(db.get(keep).unwrap().is_some());
        assert!(db.get(boundary).unwrap().is_some());
        assert!(db.get(drop).unwrap().is_none());
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
