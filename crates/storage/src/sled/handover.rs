//! [`AsmHandoverDb`] implementation backed by sled.

use anyhow::{Context, Result};
use strata_identifiers::L1BlockCommitment;
use strata_predicate::PredicateKey;

use super::{decode_block_commitment, encode_block_commitment};
use crate::AsmHandoverDb;

/// Sled-backed [`AsmHandoverDb`] keyed by [`L1BlockCommitment`].
///
/// Values are borsh-encoded; keys use the parent module's big-endian height
/// encoding so lexicographic ordering matches block-height ordering, which is
/// what lets [`Self::prune_after`] range-scan.
#[derive(Debug, Clone)]
pub struct SledAsmHandoverDb {
    handovers: sled::Tree,
}

impl SledAsmHandoverDb {
    /// Tree name the store occupies within its sled database.
    const TREE_NAME: &'static str = "asm_handovers";

    /// Opens or creates the handover tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            handovers: db.open_tree(Self::TREE_NAME)?,
        })
    }

    /// Whether `db` already contains the handover tree.
    ///
    /// [`Self::open`] creates a missing tree as a side effect. Callers that must
    /// not mutate a database they did not create check this first.
    pub fn exists_in(db: &sled::Db) -> bool {
        db.tree_names()
            .iter()
            .any(|name| name.as_ref() == Self::TREE_NAME.as_bytes())
    }

    /// Synchronous variant of [`AsmHandoverDb::put`]. The ASM worker runs on a
    /// sync thread (via `ServiceBuilder::launch_sync`), where awaiting is not
    /// possible; calling this directly avoids that.
    pub fn put(&self, block: &L1BlockCommitment, predicate: &PredicateKey) -> Result<()> {
        let value = borsh::to_vec(predicate)?;
        self.handovers
            .insert(encode_block_commitment(block), value)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmHandoverDb::get`]. See [`Self::put`].
    pub fn get(&self, block: &L1BlockCommitment) -> Result<Option<PredicateKey>> {
        match self.handovers.get(encode_block_commitment(block))? {
            Some(bytes) => Ok(Some(
                borsh::from_slice::<PredicateKey>(&bytes)
                    .context("failed to deserialize handover PredicateKey")?,
            )),
            None => Ok(None),
        }
    }

    /// Synchronous variant of [`AsmHandoverDb::prune_after`]. See [`Self::put`].
    pub fn prune_after(&self, after_height: u32) -> Result<()> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        for entry in self.handovers.range(lower..) {
            let (key, _) = entry?;
            self.handovers.remove(&key)?;
        }
        Ok(())
    }

    /// Returns every stored handover key, in ascending height order.
    ///
    /// For inspection tooling; keys are decoded without reading the values.
    pub fn list(&self) -> Result<Vec<L1BlockCommitment>> {
        self.handovers
            .iter()
            .keys()
            .map(|key| Ok(decode_block_commitment(key?.as_ref())))
            .collect()
    }
}

impl AsmHandoverDb for SledAsmHandoverDb {
    type Error = anyhow::Error;

    async fn put(&self, block: L1BlockCommitment, predicate: PredicateKey) -> Result<()> {
        self.put(&block, &predicate)
    }

    async fn get(&self, block: L1BlockCommitment) -> Result<Option<PredicateKey>> {
        self.get(&block)
    }

    async fn prune_after(&self, after_height: u32) -> Result<()> {
        self.prune_after(after_height)
    }
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::sled::test_util::{make_commitment, test_db};

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    #[test]
    fn put_get_roundtrip() {
        let (db, _dir) = test_db();
        let store = SledAsmHandoverDb::open(&db).unwrap();
        let block = make_commitment(100, 0xbb);

        store.put(&block, &predicate(1)).unwrap();
        assert_eq!(store.get(&block).unwrap(), Some(predicate(1)));
    }

    #[test]
    fn get_missing_returns_none() {
        let (db, _dir) = test_db();
        let store = SledAsmHandoverDb::open(&db).unwrap();
        assert!(store.get(&make_commitment(1, 0xcc)).unwrap().is_none());
    }

    /// Replaying a block rewrites its handover rather than accumulating entries,
    /// which is what makes the pre-commit write safe to repeat.
    #[test]
    fn put_is_idempotent_and_overwrites() {
        let (db, _dir) = test_db();
        let store = SledAsmHandoverDb::open(&db).unwrap();
        let block = make_commitment(5, 0x05);

        store.put(&block, &predicate(1)).unwrap();
        store.put(&block, &predicate(2)).unwrap();

        assert_eq!(store.get(&block).unwrap(), Some(predicate(2)));
        assert_eq!(store.list().unwrap(), vec![block]);
    }

    /// Explicit maintenance can prune a height suffix when the corresponding
    /// anchor states are pruned in the same operation.
    #[test]
    fn prune_after_removes_above_threshold_only() {
        let (db, _dir) = test_db();
        let store = SledAsmHandoverDb::open(&db).unwrap();

        let low = make_commitment(3, 0x03);
        let at = make_commitment(5, 0x05);
        let high = make_commitment(7, 0x07);
        for block in [&low, &at, &high] {
            store.put(block, &predicate(1)).unwrap();
        }

        store.prune_after(5).unwrap();

        assert!(store.get(&low).unwrap().is_some());
        assert!(store.get(&at).unwrap().is_some(), "the fork point is kept");
        assert!(store.get(&high).unwrap().is_none());
    }

    /// Runtime reorgs retain both branches. Full commitment keys isolate their
    /// handovers even when the blocks occupy the same height.
    #[test]
    fn handovers_on_sibling_branches_remain_isolated() {
        let (db, _dir) = test_db();
        let store = SledAsmHandoverDb::open(&db).unwrap();
        let branch_a = make_commitment(7, 0xaa);
        let branch_b = make_commitment(7, 0xbb);

        store.put(&branch_a, &predicate(1)).unwrap();
        store.put(&branch_b, &predicate(2)).unwrap();

        assert_eq!(store.get(&branch_a).unwrap(), Some(predicate(1)));
        assert_eq!(store.get(&branch_b).unwrap(), Some(predicate(2)));
        assert_eq!(store.list().unwrap(), vec![branch_a, branch_b]);
    }

    #[test]
    fn list_returns_keys_in_height_order() {
        let (db, _dir) = test_db();
        let store = SledAsmHandoverDb::open(&db).unwrap();
        let high = make_commitment(7, 0x07);
        let low = make_commitment(3, 0x03);
        let mid = make_commitment(5, 0x05);
        for block in [&high, &low, &mid] {
            store.put(block, &predicate(1)).unwrap();
        }

        assert_eq!(store.list().unwrap(), vec![low, mid, high]);
    }
}
