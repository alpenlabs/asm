//! Sled-backed storage for ASM anchor states and auxiliary data.

use anyhow::{Context, Result};
use strata_asm_common::AuxData;
use strata_asm_worker::AsmState;
use strata_identifiers::L1BlockCommitment;

/// Sled-backed store for ASM anchor states and auxiliary data.
///
/// Uses two sled trees:
/// - `states` — `L1BlockCommitment` → `AsmState` (borsh)
/// - `aux` — `L1BlockCommitment` → `AuxData` (borsh)
///
/// Also maintains a `latest` key pointing to the most recently stored state.
#[derive(Debug, Clone)]
pub struct AsmStateDb {
    states: sled::Tree,
    aux: sled::Tree,
    meta: sled::Tree,
}

const LATEST_KEY: &[u8] = b"latest";

impl AsmStateDb {
    /// Opens or creates the state database in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            states: db.open_tree("asm_states")?,
            aux: db.open_tree("asm_aux")?,
            meta: db.open_tree("asm_meta")?,
        })
    }

    /// Returns the most recently stored state and its block commitment.
    pub fn get_latest(&self) -> Result<Option<(L1BlockCommitment, AsmState)>> {
        let Some(key_bytes) = self.meta.get(LATEST_KEY)? else {
            return Ok(None);
        };
        let commitment = borsh::from_slice::<L1BlockCommitment>(&key_bytes)
            .context("failed to deserialize latest commitment")?;
        let state = self
            .get(&commitment)?
            .context("latest key points to missing state")?;
        Ok(Some((commitment, state)))
    }

    /// Returns the anchor state for a specific block.
    pub fn get(&self, block: &L1BlockCommitment) -> Result<Option<AsmState>> {
        let key = borsh::to_vec(block)?;
        match self.states.get(&key)? {
            Some(bytes) => {
                let state = borsh::from_slice::<AsmState>(&bytes)
                    .context("failed to deserialize AsmState")?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Stores an anchor state for the given block and updates the latest pointer.
    pub fn put(&self, block: &L1BlockCommitment, state: &AsmState) -> Result<()> {
        let key = borsh::to_vec(block)?;
        let value = borsh::to_vec(state)?;
        self.states.insert(&key, value)?;
        self.meta.insert(LATEST_KEY, key)?;
        Ok(())
    }

    /// Stores auxiliary data for a given L1 block.
    pub fn put_aux_data(&self, block: &L1BlockCommitment, data: &AuxData) -> Result<()> {
        let key = borsh::to_vec(block)?;
        let value = borsh::to_vec(data)?;
        self.aux.insert(&key, value)?;
        Ok(())
    }

    /// Retrieves auxiliary data for a given L1 block.
    pub fn get_aux_data(&self, block: &L1BlockCommitment) -> Result<Option<AuxData>> {
        let key = borsh::to_vec(block)?;
        match self.aux.get(&key)? {
            Some(bytes) => {
                let data = borsh::from_slice::<AuxData>(&bytes)
                    .context("failed to deserialize AuxData")?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_common::AuxData;
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

    use super::*;

    fn test_db() -> sled::Db {
        let dir = tempfile::tempdir().unwrap();
        sled::open(dir.path()).unwrap()
    }

    fn make_commitment(height: u32, seed: u8) -> L1BlockCommitment {
        L1BlockCommitment::new(height, L1BlockId::from(Buf32::new([seed; 32])))
    }

    #[test]
    fn get_missing_state_returns_none() {
        let db = test_db();
        let store = AsmStateDb::open(&db).unwrap();
        let commitment = make_commitment(1, 0xaa);
        assert!(store.get(&commitment).unwrap().is_none());
    }

    #[test]
    fn get_latest_on_empty_returns_none() {
        let db = test_db();
        let store = AsmStateDb::open(&db).unwrap();
        assert!(store.get_latest().unwrap().is_none());
    }

    #[test]
    fn put_aux_data_roundtrip() {
        let db = test_db();
        let store = AsmStateDb::open(&db).unwrap();
        let commitment = make_commitment(100, 0xbb);
        let aux = AuxData::default();

        store.put_aux_data(&commitment, &aux).unwrap();
        let retrieved = store.get_aux_data(&commitment).unwrap().unwrap();
        assert_eq!(
            borsh::to_vec(&retrieved).unwrap(),
            borsh::to_vec(&aux).unwrap()
        );
    }

    #[test]
    fn get_missing_aux_data_returns_none() {
        let db = test_db();
        let store = AsmStateDb::open(&db).unwrap();
        let commitment = make_commitment(1, 0xcc);
        assert!(store.get_aux_data(&commitment).unwrap().is_none());
    }
}
