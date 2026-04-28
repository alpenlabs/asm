//! Sled-backed index of per-container export entries.
//!
//! `MohoState` keeps only each container's compact MMR (peaks), so the
//! original 32-byte leaves can't be recovered from it. We mirror them here
//! so the RPC can rebuild inclusion proofs on demand.

use anyhow::{Context, Result, bail};
use strata_merkle::{MerkleProofB32, Mmr, Mmr64B32, MmrState, Sha256Hasher};

/// Stored value layout: big-endian `height` followed by `entry_hash`.
const HEIGHT_BYTES: usize = 4;
const HASH_BYTES: usize = 32;
const VALUE_LEN: usize = HEIGHT_BYTES + HASH_BYTES;

/// Forward `(container_id, mmr_index) → (height, hash)` tree, plus a
/// reverse `(container_id, hash) → mmr_index` tree for O(log N) lookups.
#[derive(Debug, Clone)]
pub struct ExportEntriesDb {
    entries: sled::Tree,
    index_by_hash: sled::Tree,
}

impl ExportEntriesDb {
    /// Opens or creates the export entries trees in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            entries: db.open_tree("export_entries")?,
            index_by_hash: db.open_tree("export_entries_by_hash")?,
        })
    }

    /// Appends an entry for `container_id` and returns its `mmr_index`.
    ///
    /// Idempotent: a duplicate `(container_id, entry)` returns the original
    /// index unchanged, so block replays after restart are a no-op. Assumes
    /// `(container_id, entry_hash)` is unique within a correct chain.
    pub fn append(&self, container_id: u8, height: u32, entry: [u8; 32]) -> Result<u64> {
        let hash_key = encode_hash_key(container_id, &entry);
        if let Some(existing) = self.index_by_hash.get(hash_key)? {
            return decode_idx(existing.as_ref());
        }

        let index = self.num_entries(container_id)?;
        let mut value = [0u8; VALUE_LEN];
        value[..HEIGHT_BYTES].copy_from_slice(&height.to_be_bytes());
        value[HEIGHT_BYTES..].copy_from_slice(&entry);

        self.entries
            .insert(encode_key(container_id, index), &value[..])?;
        self.index_by_hash.insert(hash_key, &index.to_be_bytes())?;
        Ok(index)
    }

    /// Returns the number of entries currently stored for `container_id`.
    pub fn num_entries(&self, container_id: u8) -> Result<u64> {
        Ok(self.entries.scan_prefix([container_id]).count() as u64)
    }

    /// Reverse lookup: returns `(mmr_index, insertion_height)` for `hash`
    /// under `container_id`, or `None` if absent.
    pub fn find_index(&self, container_id: u8, hash: &[u8; 32]) -> Result<Option<(u64, u32)>> {
        let hash_key = encode_hash_key(container_id, hash);
        let Some(idx_bytes) = self.index_by_hash.get(hash_key)? else {
            return Ok(None);
        };
        let mmr_index = decode_idx(idx_bytes.as_ref())?;
        let (height, _hash) = self
            .get(container_id, mmr_index)?
            .context("secondary index points at missing primary entry")?;
        Ok(Some((mmr_index, height)))
    }

    /// Fetches `(insertion_height, entry_hash)` at `(container_id, mmr_index)`.
    pub fn get(&self, container_id: u8, mmr_index: u64) -> Result<Option<(u32, [u8; 32])>> {
        match self.entries.get(encode_key(container_id, mmr_index))? {
            Some(bytes) => {
                let bytes = bytes.as_ref();
                if bytes.len() != VALUE_LEN {
                    bail!("invalid export entry value length: {}", bytes.len());
                }
                let height = u32::from_be_bytes(
                    bytes[..HEIGHT_BYTES]
                        .try_into()
                        .context("invalid height bytes in export entry")?,
                );
                let entry: [u8; HASH_BYTES] = bytes[HEIGHT_BYTES..]
                    .try_into()
                    .context("invalid hash bytes in export entry")?;
                Ok(Some((height, entry)))
            }
            None => Ok(None),
        }
    }

    /// Generates an inclusion proof for `mmr_index` against the container's
    /// MMR at size `at_leaf_count`, by replaying its first `at_leaf_count`
    /// stored leaves. Cost is O(at_leaf_count · log at_leaf_count).
    pub fn generate_proof(
        &self,
        container_id: u8,
        mmr_index: u64,
        at_leaf_count: u64,
    ) -> Result<MerkleProofB32> {
        let mut compact = Mmr64B32::new_empty();
        let mut proof_list = Vec::with_capacity(at_leaf_count as usize);

        for i in 0..at_leaf_count {
            let (_height, hash) = self.get(container_id, i)?.with_context(|| {
                format!("missing export entry at container {container_id} index {i}")
            })?;

            let proof = Mmr::<Sha256Hasher>::add_leaf_updating_proof_list(
                &mut compact,
                hash,
                &mut proof_list,
            )
            .map_err(|e| anyhow::anyhow!("MMR proof generation failed: {e}"))?;

            proof_list.push(proof);
        }

        proof_list
            .get(mmr_index as usize)
            .map(MerkleProofB32::from_generic)
            .with_context(|| format!("no proof for index {mmr_index}"))
    }
}

fn encode_key(container_id: u8, mmr_index: u64) -> [u8; 9] {
    let mut key = [0u8; 9];
    key[0] = container_id;
    key[1..].copy_from_slice(&mmr_index.to_be_bytes());
    key
}

fn encode_hash_key(container_id: u8, hash: &[u8; 32]) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[0] = container_id;
    key[1..].copy_from_slice(hash);
    key
}

fn decode_idx(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().context("invalid mmr_index bytes")?,
    ))
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};

    use super::*;

    fn test_db() -> sled::Db {
        let dir = tempfile::tempdir().unwrap();
        sled::open(dir.path()).unwrap()
    }

    fn hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn append_assigns_monotonic_indices_per_container() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        assert_eq!(store.append(1, 10, hash(0xa1)).unwrap(), 0);
        assert_eq!(store.append(1, 11, hash(0xa2)).unwrap(), 1);
        assert_eq!(store.append(2, 11, hash(0xb1)).unwrap(), 0);
        assert_eq!(store.append(1, 12, hash(0xa3)).unwrap(), 2);
        assert_eq!(store.append(2, 12, hash(0xb2)).unwrap(), 1);
    }

    #[test]
    fn num_entries_matches_appends() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        assert_eq!(store.num_entries(7).unwrap(), 0);
        for i in 0..5u8 {
            store.append(7, 100 + i as u32, hash(i)).unwrap();
        }
        assert_eq!(store.num_entries(7).unwrap(), 5);
        assert_eq!(store.num_entries(8).unwrap(), 0);
    }

    #[test]
    fn get_returns_none_for_unknown() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        store.append(1, 42, hash(0xaa)).unwrap();

        assert!(store.get(1, 1).unwrap().is_none());
        assert!(store.get(2, 0).unwrap().is_none());
    }

    #[test]
    fn get_returns_height_and_hash() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        store.append(3, 999, hash(0xcc)).unwrap();

        let (height, got) = store.get(3, 0).unwrap().unwrap();
        assert_eq!(height, 999);
        assert_eq!(got, hash(0xcc));
    }

    #[test]
    fn find_index_returns_match_with_height() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        store.append(1, 10, hash(0xa0)).unwrap();
        store.append(1, 11, hash(0xa1)).unwrap();
        store.append(1, 12, hash(0xa2)).unwrap();
        store.append(2, 10, hash(0xa1)).unwrap(); // same hash, different container

        assert_eq!(store.find_index(1, &hash(0xa1)).unwrap(), Some((1, 11)));
        assert_eq!(store.find_index(2, &hash(0xa1)).unwrap(), Some((0, 10)));
        assert_eq!(store.find_index(1, &hash(0xff)).unwrap(), None);
        assert_eq!(store.find_index(3, &hash(0xa1)).unwrap(), None);
    }

    #[test]
    fn append_is_idempotent_on_duplicate_hash() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        let idx0 = store.append(1, 10, hash(0xa0)).unwrap();
        let idx1 = store.append(1, 11, hash(0xa1)).unwrap();

        // Replay the same entry — should return the original index,
        // not bump num_entries, and not overwrite the original (height, hash).
        let replay_idx = store.append(1, 999, hash(0xa0)).unwrap();
        assert_eq!(replay_idx, idx0);
        assert_eq!(store.num_entries(1).unwrap(), 2);
        assert_eq!(store.get(1, idx0).unwrap().unwrap(), (10, hash(0xa0)));
        assert_eq!(store.get(1, idx1).unwrap().unwrap(), (11, hash(0xa1)));
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();

        {
            let db = sled::open(dir.path()).unwrap();
            let store = ExportEntriesDb::open(&db).unwrap();
            store.append(2, 5, hash(0x42)).unwrap();
            store.append(2, 6, hash(0x43)).unwrap();
        }

        {
            let db = sled::open(dir.path()).unwrap();
            let store = ExportEntriesDb::open(&db).unwrap();
            assert_eq!(store.num_entries(2).unwrap(), 2);
            assert_eq!(store.get(2, 0).unwrap().unwrap(), (5, hash(0x42)));
            assert_eq!(store.get(2, 1).unwrap().unwrap(), (6, hash(0x43)));
            assert_eq!(store.find_index(2, &hash(0x43)).unwrap(), Some((1, 6)));
        }
    }

    fn rebuild_compact_mmr(store: &ExportEntriesDb, container_id: u8, size: u64) -> Mmr64B32 {
        let mut compact = Mmr64B32::new_empty();
        for i in 0..size {
            let (_h, hash) = store.get(container_id, i).unwrap().unwrap();
            Mmr::<Sha256Hasher>::add_leaf(&mut compact, hash).unwrap();
        }
        compact
    }

    #[test]
    fn generate_and_verify_proof_single_leaf() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        let h = hash(0x01);
        store.append(4, 100, h).unwrap();

        let proof = store.generate_proof(4, 0, 1).unwrap();
        let compact = rebuild_compact_mmr(&store, 4, 1);
        assert!(compact.verify(&proof, &h));
    }

    #[test]
    fn generate_proofs_for_all_leaves() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        for i in 0u8..8 {
            store.append(5, 1000 + i as u32, hash(i)).unwrap();
        }

        for i in 0u64..8 {
            store
                .generate_proof(5, i, 8)
                .unwrap_or_else(|e| panic!("proof generation failed for leaf {i}: {e}"));
        }
    }

    #[test]
    fn proof_at_earlier_size_is_valid() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();

        for i in 0u8..4 {
            store.append(6, 100 + i as u32, hash(i)).unwrap();
        }
        let compact_at_4 = rebuild_compact_mmr(&store, 6, 4);

        for i in 4u8..8 {
            store.append(6, 100 + i as u32, hash(i)).unwrap();
        }

        let proof = store.generate_proof(6, 2, 4).unwrap();
        assert!(compact_at_4.verify(&proof, &hash(2)));
    }

    #[test]
    fn proof_ssz_roundtrip_verifies() {
        let db = test_db();
        let store = ExportEntriesDb::open(&db).unwrap();
        for i in 0u8..5 {
            store.append(9, 200 + i as u32, hash(i)).unwrap();
        }

        let proof = store.generate_proof(9, 3, 5).unwrap();
        let bytes = proof.as_ssz_bytes();
        let decoded = MerkleProofB32::from_ssz_bytes(&bytes).unwrap();

        let compact = rebuild_compact_mmr(&store, 9, 5);
        assert!(compact.verify(&decoded, &hash(3)));
    }
}
