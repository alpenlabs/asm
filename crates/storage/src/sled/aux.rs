//! [`AsmAuxDataDb`] implementation backed by sled.

use anyhow::{Context, Result};
use strata_asm_common::AuxData;
use strata_identifiers::L1BlockCommitment;

use super::{decode_block_commitment, encode_block_commitment};
use crate::AsmAuxDataDb;

/// Sled-backed [`AsmAuxDataDb`] keyed by [`L1BlockCommitment`].
///
/// Values are borsh-encoded; keys use the parent module's big-endian height
/// encoding so lexicographic ordering matches block-height ordering.
#[derive(Debug, Clone)]
pub struct SledAsmAuxDataDb {
    aux: sled::Tree,
}

impl SledAsmAuxDataDb {
    /// Opens or creates the auxiliary-data tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            aux: db.open_tree("asm_aux")?,
        })
    }

    /// Synchronous variant of [`AsmAuxDataDb::put`]. The ASM worker runs on a
    /// sync thread (via `ServiceBuilder::launch_sync`), where awaiting is not
    /// possible; calling this directly avoids that.
    pub fn put(&self, block: &L1BlockCommitment, data: &AuxData) -> Result<()> {
        let value = borsh::to_vec(data)?;
        self.aux.insert(encode_block_commitment(block), value)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmAuxDataDb::get`]. See [`Self::put`].
    pub fn get(&self, block: &L1BlockCommitment) -> Result<Option<AuxData>> {
        match self.aux.get(encode_block_commitment(block))? {
            Some(bytes) => {
                let data = borsh::from_slice::<AuxData>(&bytes)
                    .context("failed to deserialize AuxData")?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Synchronous variant of [`AsmAuxDataDb::prune_before`]. See [`Self::put`].
    pub fn prune_before(&self, before_height: u32) -> Result<()> {
        let upper: &[u8] = &before_height.to_be_bytes();
        for entry in self.aux.range(..upper) {
            let (key, _) = entry?;
            self.aux.remove(&key)?;
        }
        Ok(())
    }

    /// Synchronous variant of [`AsmAuxDataDb::prune_after`]. See [`Self::put`].
    pub fn prune_after(&self, after_height: u32) -> Result<()> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        for entry in self.aux.range(lower..) {
            let (key, _) = entry?;
            self.aux.remove(&key)?;
        }
        Ok(())
    }

    /// Removes the auxiliary data for `block`, returning whether it was present.
    ///
    /// For inspection tooling; the worker never deletes individual entries.
    pub fn delete(&self, block: &L1BlockCommitment) -> Result<bool> {
        Ok(self.aux.remove(encode_block_commitment(block))?.is_some())
    }

    /// Returns every stored auxiliary-data key, in ascending height order.
    ///
    /// For inspection tooling: keys are decoded from the tree without reading
    /// the values.
    pub fn list(&self) -> Result<Vec<L1BlockCommitment>> {
        self.aux
            .iter()
            .keys()
            .map(|key| Ok(decode_block_commitment(key?.as_ref())))
            .collect()
    }
}

impl AsmAuxDataDb for SledAsmAuxDataDb {
    type Error = anyhow::Error;

    async fn put(&self, block: L1BlockCommitment, data: AuxData) -> Result<()> {
        self.put(&block, &data)
    }

    async fn get(&self, block: L1BlockCommitment) -> Result<Option<AuxData>> {
        self.get(&block)
    }

    async fn prune_before(&self, before_height: u32) -> Result<()> {
        self.prune_before(before_height)
    }

    async fn prune_after(&self, after_height: u32) -> Result<()> {
        self.prune_after(after_height)
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_common::AuxData;

    use super::*;
    use crate::sled::test_util::{make_commitment, test_db};

    fn assert_aux_eq(a: &AuxData, b: &AuxData) {
        assert_eq!(borsh::to_vec(a).unwrap(), borsh::to_vec(b).unwrap());
    }

    #[test]
    fn put_get_roundtrip() {
        let (db, _dir) = test_db();
        let store = SledAsmAuxDataDb::open(&db).unwrap();
        let commitment = make_commitment(100, 0xbb);
        let aux = AuxData::default();

        store.put(&commitment, &aux).unwrap();
        let retrieved = store.get(&commitment).unwrap().unwrap();
        assert_aux_eq(&retrieved, &aux);
    }

    #[test]
    fn get_missing_returns_none() {
        let (db, _dir) = test_db();
        let store = SledAsmAuxDataDb::open(&db).unwrap();
        let commitment = make_commitment(1, 0xcc);
        assert!(store.get(&commitment).unwrap().is_none());
    }

    #[test]
    fn prune_before_removes_below_threshold_only() {
        let (db, _dir) = test_db();
        let store = SledAsmAuxDataDb::open(&db).unwrap();
        let aux = AuxData::default();

        let low = make_commitment(3, 0x03);
        let at = make_commitment(5, 0x05);
        let high = make_commitment(7, 0x07);
        store.put(&low, &aux).unwrap();
        store.put(&at, &aux).unwrap();
        store.put(&high, &aux).unwrap();

        store.prune_before(5).unwrap();

        assert!(store.get(&low).unwrap().is_none());
        assert!(store.get(&at).unwrap().is_some());
        assert!(store.get(&high).unwrap().is_some());
    }

    #[test]
    fn prune_after_removes_above_threshold_only() {
        let (db, _dir) = test_db();
        let store = SledAsmAuxDataDb::open(&db).unwrap();
        let aux = AuxData::default();

        let low = make_commitment(3, 0x03);
        let at = make_commitment(5, 0x05);
        let high = make_commitment(7, 0x07);
        store.put(&low, &aux).unwrap();
        store.put(&at, &aux).unwrap();
        store.put(&high, &aux).unwrap();

        store.prune_after(5).unwrap();

        assert!(store.get(&low).unwrap().is_some());
        assert!(store.get(&at).unwrap().is_some());
        assert!(store.get(&high).unwrap().is_none());
    }

    #[test]
    fn delete_reports_presence_and_removes() {
        let (db, _dir) = test_db();
        let store = SledAsmAuxDataDb::open(&db).unwrap();
        let commitment = make_commitment(42, 0xdd);
        store.put(&commitment, &AuxData::default()).unwrap();

        assert!(store.delete(&commitment).unwrap());
        assert!(store.get(&commitment).unwrap().is_none());
        // Deleting again reports absence.
        assert!(!store.delete(&commitment).unwrap());
    }

    #[test]
    fn list_returns_keys_in_height_order() {
        let (db, _dir) = test_db();
        let store = SledAsmAuxDataDb::open(&db).unwrap();
        let high = make_commitment(7, 0x07);
        let low = make_commitment(3, 0x03);
        let mid = make_commitment(5, 0x05);
        // Insert out of order; list must come back height-sorted.
        store.put(&high, &AuxData::default()).unwrap();
        store.put(&low, &AuxData::default()).unwrap();
        store.put(&mid, &AuxData::default()).unwrap();

        assert_eq!(store.list().unwrap(), vec![low, mid, high]);
    }
}
