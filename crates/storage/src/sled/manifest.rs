//! [`AsmManifestDb`] implementation backed by sled.

use anyhow::{Context, Result};
use strata_asm_common::AsmManifest;
use strata_identifiers::L1BlockCommitment;

use super::encode_block_commitment;
use crate::AsmManifestDb;

/// Sled-backed [`AsmManifestDb`] keyed by [`L1BlockCommitment`].
///
/// Values are borsh-encoded; keys use the parent module's big-endian height
/// encoding so lexicographic ordering matches block-height ordering.
#[derive(Debug, Clone)]
pub struct SledAsmManifestDb {
    manifests: sled::Tree,
}

impl SledAsmManifestDb {
    /// Opens or creates the manifest tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            manifests: db.open_tree("asm_manifests")?,
        })
    }

    /// Synchronous variant of [`AsmManifestDb::put`]. The ASM worker runs on a
    /// sync thread (via `ServiceBuilder::launch_sync`), where awaiting is not
    /// possible; calling this directly avoids that.
    pub fn put(&self, manifest: &AsmManifest) -> Result<()> {
        let block = L1BlockCommitment::new(manifest.height(), *manifest.blkid());
        let value = borsh::to_vec(manifest)?;
        self.manifests
            .insert(encode_block_commitment(&block), value)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmManifestDb::get`]. See [`Self::put`].
    pub fn get(&self, block: &L1BlockCommitment) -> Result<Option<AsmManifest>> {
        match self.manifests.get(encode_block_commitment(block))? {
            Some(bytes) => {
                let manifest = borsh::from_slice::<AsmManifest>(&bytes)
                    .context("failed to deserialize AsmManifest")?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// Synchronous variant of [`AsmManifestDb::prune_before`]. See [`Self::put`].
    pub fn prune_before(&self, before_height: u32) -> Result<()> {
        let upper: &[u8] = &before_height.to_be_bytes();
        for entry in self.manifests.range(..upper) {
            let (key, _) = entry?;
            self.manifests.remove(&key)?;
        }
        Ok(())
    }

    /// Synchronous variant of [`AsmManifestDb::prune_after`]. See [`Self::put`].
    pub fn prune_after(&self, after_height: u32) -> Result<()> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        for entry in self.manifests.range(lower..) {
            let (key, _) = entry?;
            self.manifests.remove(&key)?;
        }
        Ok(())
    }
}

impl AsmManifestDb for SledAsmManifestDb {
    type Error = anyhow::Error;

    async fn put(&self, manifest: AsmManifest) -> Result<()> {
        self.put(&manifest)
    }

    async fn get(&self, block: L1BlockCommitment) -> Result<Option<AsmManifest>> {
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
    use strata_asm_common::AsmManifest;
    use strata_identifiers::{Buf32, L1BlockId, WtxidsRoot};

    use super::*;
    use crate::sled::test_util::{make_commitment, test_db};

    fn make_manifest(height: u32, seed: u8) -> AsmManifest {
        AsmManifest::new(
            height,
            L1BlockId::from(Buf32::new([seed; 32])),
            WtxidsRoot::from(Buf32::new([seed; 32])),
            vec![],
        )
        .unwrap()
    }

    fn assert_manifest_eq(a: &AsmManifest, b: &AsmManifest) {
        assert_eq!(borsh::to_vec(a).unwrap(), borsh::to_vec(b).unwrap());
    }

    #[test]
    fn put_get_roundtrip() {
        let (db, _dir) = test_db();
        let store = SledAsmManifestDb::open(&db).unwrap();
        let commitment = make_commitment(100, 0xbb);
        let manifest = make_manifest(100, 0xbb);

        store.put(&manifest).unwrap();
        let retrieved = store.get(&commitment).unwrap().unwrap();
        assert_manifest_eq(&retrieved, &manifest);
    }

    #[test]
    fn get_missing_returns_none() {
        let (db, _dir) = test_db();
        let store = SledAsmManifestDb::open(&db).unwrap();
        let commitment = make_commitment(1, 0xcc);
        assert!(store.get(&commitment).unwrap().is_none());
    }

    #[test]
    fn prune_before_removes_below_threshold_only() {
        let (db, _dir) = test_db();
        let store = SledAsmManifestDb::open(&db).unwrap();

        let low = make_commitment(3, 0x03);
        let at = make_commitment(5, 0x05);
        let high = make_commitment(7, 0x07);
        store.put(&make_manifest(3, 0x03)).unwrap();
        store.put(&make_manifest(5, 0x05)).unwrap();
        store.put(&make_manifest(7, 0x07)).unwrap();

        store.prune_before(5).unwrap();

        assert!(store.get(&low).unwrap().is_none());
        assert!(store.get(&at).unwrap().is_some());
        assert!(store.get(&high).unwrap().is_some());
    }

    #[test]
    fn prune_after_removes_above_threshold_only() {
        let (db, _dir) = test_db();
        let store = SledAsmManifestDb::open(&db).unwrap();

        let low = make_commitment(3, 0x03);
        let at = make_commitment(5, 0x05);
        let high = make_commitment(7, 0x07);
        store.put(&make_manifest(3, 0x03)).unwrap();
        store.put(&make_manifest(5, 0x05)).unwrap();
        store.put(&make_manifest(7, 0x07)).unwrap();

        store.prune_after(5).unwrap();

        assert!(store.get(&low).unwrap().is_some());
        assert!(store.get(&at).unwrap().is_some());
        assert!(store.get(&high).unwrap().is_none());
    }
}
