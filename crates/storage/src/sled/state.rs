//! [`AsmStateDb`] implementation backed by sled.

use anyhow::{Context, Result};
use strata_asm_common::AnchorState;
use strata_identifiers::L1BlockCommitment;

use super::encode_block_commitment;
use crate::AsmStateDb;

/// Sled-backed [`AsmStateDb`] keyed by [`L1BlockCommitment`].
///
/// Values are borsh-encoded; keys use the parent module's big-endian height
/// encoding so lexicographic ordering matches block-height ordering.
#[derive(Debug, Clone)]
pub struct SledAsmStateDb {
    states: sled::Tree,
}

impl SledAsmStateDb {
    /// Opens or creates the anchor-state tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            states: db.open_tree("asm_states")?,
        })
    }

    /// Synchronous variant of [`AsmStateDb::put`]. The ASM worker runs on a sync
    /// thread (via `ServiceBuilder::launch_sync`), where awaiting is not
    /// possible; calling this directly avoids that.
    pub fn put(&self, state: &AnchorState) -> Result<()> {
        let key = encode_block_commitment(&state.chain_view.pow_state.last_verified_block);
        let value = borsh::to_vec(state)?;
        self.states.insert(key, value)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmStateDb::get`]. See [`Self::put`].
    pub fn get(&self, block: &L1BlockCommitment) -> Result<Option<AnchorState>> {
        match self.states.get(encode_block_commitment(block))? {
            Some(bytes) => {
                let state = borsh::from_slice::<AnchorState>(&bytes)
                    .context("failed to deserialize AnchorState")?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Synchronous variant of [`AsmStateDb::get_latest`]. See [`Self::put`].
    pub fn get_latest(&self) -> Result<Option<AnchorState>> {
        let Some((_, bytes)) = self.states.last()? else {
            return Ok(None);
        };
        let state = borsh::from_slice::<AnchorState>(&bytes)
            .context("failed to deserialize AnchorState")?;
        Ok(Some(state))
    }

    /// Synchronous variant of [`AsmStateDb::prune_before`]. See [`Self::put`].
    pub fn prune_before(&self, before_height: u32) -> Result<()> {
        let upper: &[u8] = &before_height.to_be_bytes();
        for entry in self.states.range(..upper) {
            let (key, _) = entry?;
            self.states.remove(&key)?;
        }
        Ok(())
    }

    /// Synchronous variant of [`AsmStateDb::prune_after`]. See [`Self::put`].
    pub fn prune_after(&self, after_height: u32) -> Result<()> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        for entry in self.states.range(lower..) {
            let (key, _) = entry?;
            self.states.remove(&key)?;
        }
        Ok(())
    }
}

impl AsmStateDb for SledAsmStateDb {
    type Error = anyhow::Error;

    async fn put(&self, state: AnchorState) -> Result<()> {
        self.put(&state)
    }

    async fn get(&self, block: L1BlockCommitment) -> Result<Option<AnchorState>> {
        self.get(&block)
    }

    async fn get_latest(&self) -> Result<Option<AnchorState>> {
        self.get_latest()
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
    use super::*;
    use crate::sled::test_util::{make_commitment, test_db};

    #[test]
    fn get_missing_state_returns_none() {
        let (db, _dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        let commitment = make_commitment(1, 0xaa);
        assert!(store.get(&commitment).unwrap().is_none());
    }

    #[test]
    fn get_latest_on_empty_returns_none() {
        let (db, _dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        assert!(store.get_latest().unwrap().is_none());
    }

    // Constructing an `AnchorState` requires a full pow/accumulator state, so
    // value-bearing round-trips are not exercised here: put/get/prune share
    // their key-encoding and sled logic with the aux and manifest stores (tested
    // there), and `get_latest` relies on the same big-endian-ordering guarantee
    // that those stores' prune range tests cover.
}
