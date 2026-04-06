//! Sled-backed Merkle Mountain Range for manifest hashes.

use anyhow::{Context, Result};
use strata_identifiers::Buf32;
use strata_merkle::{CompactMmr64, MerkleProofB32, Mmr, Sha256Hasher};

/// Sled-backed MMR for manifest hashes.
///
/// Stores individual leaves (manifest hashes) and the compact MMR state.
/// Proof generation rebuilds a full MMR from stored leaves on demand.
#[derive(Debug, Clone)]
pub struct MmrDb {
    leaves: sled::Tree,
    meta: sled::Tree,
}

const MMR_STATE_KEY: &[u8] = b"mmr_compact";
const LEAF_COUNT_KEY: &[u8] = b"leaf_count";

impl MmrDb {
    /// Opens or creates the MMR database in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            leaves: db.open_tree("mmr_leaves")?,
            meta: db.open_tree("mmr_meta")?,
        })
    }

    /// Returns the current leaf count.
    pub fn leaf_count(&self) -> Result<u64> {
        match self.meta.get(LEAF_COUNT_KEY)? {
            Some(bytes) => {
                let count = u64::from_le_bytes(
                    bytes
                        .as_ref()
                        .try_into()
                        .context("invalid leaf count bytes")?,
                );
                Ok(count)
            }
            None => Ok(0),
        }
    }

    /// Appends a manifest hash as a new leaf. Returns the leaf index.
    pub fn append_leaf(&self, hash: Buf32) -> Result<u64> {
        let index = self.leaf_count()?;

        // Store the leaf.
        self.leaves.insert(index.to_le_bytes(), hash.0.as_slice())?;

        // Update compact MMR.
        let mut compact = self.load_compact_mmr()?;
        Mmr::<Sha256Hasher>::add_leaf(&mut compact, hash.0)
            .map_err(|e| anyhow::anyhow!("MMR append failed: {e}"))?;
        self.save_compact_mmr(&compact)?;

        // Update leaf count.
        self.meta
            .insert(LEAF_COUNT_KEY, &(index + 1).to_le_bytes())?;

        Ok(index)
    }

    /// Retrieves a manifest hash by its leaf index.
    pub fn get_leaf(&self, index: u64) -> Result<Option<Buf32>> {
        match self.leaves.get(index.to_le_bytes())? {
            Some(bytes) => {
                let arr: [u8; 32] = bytes
                    .as_ref()
                    .try_into()
                    .context("invalid leaf hash bytes")?;
                Ok(Some(Buf32::new(arr)))
            }
            None => Ok(None),
        }
    }

    /// Generates an MMR inclusion proof for a leaf at a specific MMR size.
    ///
    /// Rebuilds the MMR from stored leaves up to `at_leaf_count`, then
    /// extracts the proof for the given index.
    pub fn generate_proof(&self, index: u64, at_leaf_count: u64) -> Result<MerkleProofB32> {
        let mut compact = CompactMmr64::new(64);
        let mut proof_list = Vec::with_capacity(at_leaf_count as usize);

        for i in 0..at_leaf_count {
            let hash = self
                .get_leaf(i)?
                .context(format!("missing leaf at index {i}"))?;

            let proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                &mut compact,
                hash.0,
                &mut proof_list,
            )
            .map_err(|e| anyhow::anyhow!("MMR proof generation failed: {e}"))?;

            proof_list.push(proof);
        }

        proof_list
            .get(index as usize)
            .map(MerkleProofB32::from_generic)
            .context(format!("no proof for index {index}"))
    }

    fn load_compact_mmr(&self) -> Result<CompactMmr64<[u8; 32]>> {
        match self.meta.get(MMR_STATE_KEY)? {
            Some(bytes) => borsh::from_slice(&bytes).context("failed to deserialize compact MMR"),
            None => Ok(CompactMmr64::new(64)),
        }
    }

    fn save_compact_mmr(&self, mmr: &CompactMmr64<[u8; 32]>) -> Result<()> {
        let bytes = borsh::to_vec(mmr)?;
        self.meta.insert(MMR_STATE_KEY, bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use strata_identifiers::Buf32;
    use strata_merkle::Mmr64B32;

    use super::*;

    fn test_db() -> sled::Db {
        let dir = tempfile::tempdir().unwrap();
        sled::open(dir.path()).unwrap()
    }

    fn make_leaf(seed: u8) -> Buf32 {
        Buf32::new([seed; 32])
    }

    #[test]
    fn empty_mmr_has_zero_leaves() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();
        assert_eq!(mmr.leaf_count().unwrap(), 0);
    }

    #[test]
    fn append_and_retrieve_leaf() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();
        let leaf = make_leaf(0xaa);

        let idx = mmr.append_leaf(leaf).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(mmr.leaf_count().unwrap(), 1);

        let retrieved = mmr.get_leaf(0).unwrap().unwrap();
        assert_eq!(retrieved, leaf);
    }

    #[test]
    fn append_multiple_leaves() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();

        for i in 0u8..5 {
            let idx = mmr.append_leaf(make_leaf(i)).unwrap();
            assert_eq!(idx, i as u64);
        }

        assert_eq!(mmr.leaf_count().unwrap(), 5);

        for i in 0u8..5 {
            let leaf = mmr.get_leaf(i as u64).unwrap().unwrap();
            assert_eq!(leaf, make_leaf(i));
        }
    }

    #[test]
    fn get_missing_leaf_returns_none() {
        let db = test_db();
        let mmr = MmrDb::open(&db).unwrap();
        assert!(mmr.get_leaf(0).unwrap().is_none());
    }

    #[test]
    fn generate_and_verify_proof_single_leaf() {
        let db = test_db();
        let mmr_db = MmrDb::open(&db).unwrap();
        let leaf = make_leaf(0x01);
        mmr_db.append_leaf(leaf).unwrap();

        let proof = mmr_db.generate_proof(0, 1).unwrap();
        let compact = Mmr64B32::from_generic(&mmr_db.load_compact_mmr().unwrap());
        assert!(compact.verify(&proof, &leaf.0));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let mmr_db = MmrDb::open(&db).unwrap();

        for i in 0u8..8 {
            mmr_db.append_leaf(make_leaf(i)).unwrap();
        }

        // Generating a proof for each leaf should succeed.
        for i in 0u64..8 {
            mmr_db
                .generate_proof(i, 8)
                .unwrap_or_else(|e| panic!("proof generation failed for leaf {i}: {e}"));
        }
    }

    #[test]
    fn proof_at_earlier_size_is_valid() {
        let db = test_db();
        let mmr_db = MmrDb::open(&db).unwrap();

        // Append 4 leaves, snapshot the compact state.
        for i in 0u8..4 {
            mmr_db.append_leaf(make_leaf(i)).unwrap();
        }
        let compact_at_4 = Mmr64B32::from_generic(&mmr_db.load_compact_mmr().unwrap());

        // Append 4 more.
        for i in 4u8..8 {
            mmr_db.append_leaf(make_leaf(i)).unwrap();
        }

        // Proof at size 4 should verify against the snapshot.
        let proof = mmr_db.generate_proof(2, 4).unwrap();
        assert!(compact_at_4.verify(&proof, &make_leaf(2).0));
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();

        {
            let db = sled::open(dir.path()).unwrap();
            let mmr = MmrDb::open(&db).unwrap();
            mmr.append_leaf(make_leaf(0x42)).unwrap();
            mmr.append_leaf(make_leaf(0x43)).unwrap();
        }

        {
            let db = sled::open(dir.path()).unwrap();
            let mmr = MmrDb::open(&db).unwrap();
            assert_eq!(mmr.leaf_count().unwrap(), 2);
            assert_eq!(mmr.get_leaf(0).unwrap().unwrap(), make_leaf(0x42));
            assert_eq!(mmr.get_leaf(1).unwrap().unwrap(), make_leaf(0x43));
        }
    }
}
