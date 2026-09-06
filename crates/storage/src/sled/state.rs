//! [`AsmStateDb`] implementation backed by sled.

use anyhow::{Result, anyhow};
use ssz::Encode;
use strata_asm_common::AnchorState;
use strata_identifiers::L1BlockCommitment;

use super::{decode_block_commitment, encode_block_commitment};
use crate::AsmStateDb;

/// Metadata key holding the block commitment of the worker's active tip.
///
/// State keys are always 36 bytes. This one-byte key cannot collide with one
/// and sorts before every valid state key, so range operations can skip it
/// without disturbing the state-key ordering.
const ACTIVE_TIP_KEY: &[u8] = b"\0";

/// Marker used when a manual prune/delete removes the active state.
///
/// A missing metadata entry is valid only for an empty fresh store. This
/// explicit marker records that maintenance deliberately removed the active
/// tip, so retained branch snapshots are not selected implicitly.
const NO_ACTIVE_TIP: &[u8] = b"none";

/// Sled-backed [`AsmStateDb`] keyed by [`L1BlockCommitment`].
///
/// Values are SSZ-encoded (the canonical state encoding); keys use the parent
/// module's big-endian height encoding so lexicographic ordering matches
/// block-height ordering.
#[derive(Debug, Clone)]
pub struct SledAsmStateDb {
    states: sled::Tree,
}

impl SledAsmStateDb {
    /// Tree name the store occupies within its sled database.
    const TREE_NAME: &'static str = "asm_states";

    /// Opens or creates the anchor-state tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            states: db.open_tree(Self::TREE_NAME)?,
        })
    }

    /// Whether `db` already contains the anchor-state tree.
    ///
    /// [`Self::open`] creates a missing tree as a side effect. Callers that
    /// must not mutate a database they did not create — offline tooling
    /// probing an operator-supplied path — check this before opening.
    pub fn exists_in(db: &sled::Db) -> bool {
        db.tree_names()
            .iter()
            .any(|name| name.as_ref() == Self::TREE_NAME.as_bytes())
    }

    /// Synchronous variant of [`AsmStateDb::put`]. Stores a block-addressable
    /// snapshot without selecting it as the worker's active tip.
    pub fn put(&self, state: &AnchorState) -> Result<()> {
        let key = encode_block_commitment(&state.chain_view.pow_state.last_verified_block);
        let value = state.as_ssz_bytes();
        self.states.insert(key, value)?;
        Ok(())
    }

    /// Atomically stores `state` and selects it as the durable active tip.
    ///
    /// Worker commits use this method. Keeping it separate from [`Self::put`]
    /// prevents an offline historical-state write from changing restart state.
    pub fn commit(&self, state: &AnchorState) -> Result<()> {
        let key = encode_block_commitment(&state.chain_view.pow_state.last_verified_block);
        let value = state.as_ssz_bytes();

        // The state and its active-tip pointer are one commit. Orphaned states
        // remain addressable by their full block commitment, while restart
        // resumes from the last branch the worker actually adopted rather than
        // from whichever retained key happens to sort highest.
        let mut batch = sled::Batch::default();
        batch.insert(key.as_slice(), value);
        batch.insert(ACTIVE_TIP_KEY, key.as_slice());
        self.states.apply_batch(batch)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmStateDb::get`]. See [`Self::put`].
    pub fn get(&self, block: &L1BlockCommitment) -> Result<Option<AnchorState>> {
        match self.states.get(encode_block_commitment(block))? {
            Some(bytes) => {
                let state = decode_state(&bytes)?;
                validate_state_key(*block, &state)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Synchronous variant of [`AsmStateDb::get_latest`]. See [`Self::put`].
    pub fn get_latest(&self) -> Result<Option<(L1BlockCommitment, AnchorState)>> {
        validate_tree_keys(&self.states)?;
        let state_key = match self.states.get(ACTIVE_TIP_KEY)? {
            Some(marker) if marker.as_ref() == NO_ACTIVE_TIP => return Ok(None),
            Some(key) => {
                if key.len() != super::ENCODED_L1_COMMITMENT_SIZE {
                    return Err(anyhow!(
                        "invalid ASM active-tip key length: expected {}, got {}",
                        super::ENCODED_L1_COMMITMENT_SIZE,
                        key.len(),
                    ));
                }
                key
            }
            None if has_state_rows(&self.states)? => {
                return Err(anyhow!(
                    "ASM state store has states but no active-tip record"
                ));
            }
            None => return Ok(None),
        };

        let block = decode_block_commitment(&state_key);
        let bytes = self
            .states
            .get(&state_key)?
            .ok_or_else(|| anyhow!("ASM active tip {} has no stored anchor state", block))?;
        let state = decode_state(&bytes)?;
        validate_state_key(block, &state)?;
        Ok(Some((block, state)))
    }

    /// Synchronous variant of [`AsmStateDb::prune_before`]. See [`Self::put`].
    pub fn prune_before(&self, before_height: u32) -> Result<()> {
        let upper: &[u8] = &before_height.to_be_bytes();
        let active = self.active_tip_key()?;
        let mut batch = sled::Batch::default();
        for entry in self.states.range(..upper) {
            let (key, _) = entry?;
            if is_state_key(&key) {
                batch.remove(key);
            }
        }
        if active.is_some_and(|key| decode_block_commitment(&key).height() < before_height) {
            batch.insert(ACTIVE_TIP_KEY, NO_ACTIVE_TIP);
        }
        self.states.apply_batch(batch)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmStateDb::prune_after`]. See [`Self::put`].
    pub fn prune_after(&self, after_height: u32) -> Result<()> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        let active = self.active_tip_key()?;
        let mut batch = sled::Batch::default();
        for entry in self.states.range(lower..) {
            let (key, _) = entry?;
            if is_state_key(&key) {
                batch.remove(key);
            }
        }
        if active.is_some_and(|key| decode_block_commitment(&key).height() > after_height) {
            batch.insert(ACTIVE_TIP_KEY, NO_ACTIVE_TIP);
        }
        self.states.apply_batch(batch)?;
        Ok(())
    }

    /// Removes the anchor state for `block`, returning whether one was present.
    ///
    /// For inspection tooling; the worker never deletes individual states.
    pub fn delete(&self, block: &L1BlockCommitment) -> Result<bool> {
        let key = encode_block_commitment(block);
        let was_active = self.active_tip_key()?.as_deref() == Some(key.as_slice());
        let existed = self.states.contains_key(key)?;
        if !existed {
            return Ok(false);
        }

        let mut batch = sled::Batch::default();
        batch.remove(key.as_slice());
        if was_active {
            batch.insert(ACTIVE_TIP_KEY, NO_ACTIVE_TIP);
        }
        self.states.apply_batch(batch)?;
        Ok(true)
    }

    /// Returns every stored anchor-state key, in ascending height order.
    ///
    /// For inspection tooling: keys are decoded from the tree without reading
    /// the (large) values.
    pub fn list(&self) -> Result<Vec<L1BlockCommitment>> {
        validate_tree_keys(&self.states)?;
        self.states
            .iter()
            .keys()
            .filter_map(|key| match key {
                Ok(key) if is_state_key(&key) => Some(Ok(decode_block_commitment(&key))),
                Ok(_) => None,
                Err(error) => Some(Err(error.into())),
            })
            .collect()
    }

    /// Returns whether an anchor state is stored for `block`.
    ///
    /// Checks key presence only — it does not read or decode the (large) value.
    /// Used by startup proof recovery to test whether a specific canonical block
    /// has been processed.
    pub fn contains(&self, block: &L1BlockCommitment) -> Result<bool> {
        Ok(self.states.contains_key(encode_block_commitment(block))?)
    }

    /// Returns the raw active-tip state key, distinguishing a missing/corrupt
    /// active record from one whose active state was explicitly removed.
    fn active_tip_key(&self) -> Result<Option<sled::IVec>> {
        validate_tree_keys(&self.states)?;
        match self.states.get(ACTIVE_TIP_KEY)? {
            Some(marker) if marker.as_ref() == NO_ACTIVE_TIP => Ok(None),
            Some(key) if is_state_key(&key) => Ok(Some(key)),
            Some(key) => Err(anyhow!(
                "invalid ASM active-tip key length: expected {}, got {}",
                super::ENCODED_L1_COMMITMENT_SIZE,
                key.len(),
            )),
            None if has_state_rows(&self.states)? => Err(anyhow!(
                "ASM state store has states but no active-tip record"
            )),
            None => Ok(None),
        }
    }
}

fn is_state_key(key: &[u8]) -> bool {
    key.len() == super::ENCODED_L1_COMMITMENT_SIZE
}

fn decode_state(bytes: &[u8]) -> Result<AnchorState> {
    AnchorState::decode_canonical(bytes)
        .map_err(|e| anyhow!("failed to deserialize canonical AnchorState: {e}"))
}

/// Rejects a state row whose value claims a different block than its key.
///
/// The active-tip record selects the key, while the STF reads the commitment
/// embedded in the value. Both must name the same block or callers could adopt
/// one state while recording a different in-memory tip.
fn validate_state_key(expected: L1BlockCommitment, state: &AnchorState) -> Result<()> {
    let actual = state.last_processed_block();
    if actual != expected {
        return Err(anyhow!(
            "ASM state key {expected} contains anchor state for {actual}"
        ));
    }
    Ok(())
}

fn validate_tree_keys(states: &sled::Tree) -> Result<()> {
    for entry in states.iter().keys() {
        let key = entry?;
        if key.as_ref() != ACTIVE_TIP_KEY && !is_state_key(&key) {
            return Err(anyhow!(
                "ASM state store has an unrecognized key of {} bytes",
                key.len(),
            ));
        }
    }
    Ok(())
}

fn has_state_rows(states: &sled::Tree) -> Result<bool> {
    for entry in states.iter().keys() {
        if is_state_key(&entry?) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl AsmStateDb for SledAsmStateDb {
    type Error = anyhow::Error;

    async fn put(&self, state: AnchorState) -> Result<()> {
        self.put(&state)
    }

    async fn get(&self, block: L1BlockCommitment) -> Result<Option<AnchorState>> {
        self.get(&block)
    }

    async fn get_latest(&self) -> Result<Option<(L1BlockCommitment, AnchorState)>> {
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
    use strata_asm_common::{
        ANCHOR_STATE_VERSION, AsmHistoryAccumulatorState, ChainViewState, HeaderVerificationState,
    };

    use super::*;
    use crate::sled::test_util::{make_commitment, test_db};

    fn state_at(block: L1BlockCommitment) -> AnchorState {
        let mut pow_state = HeaderVerificationState::default();
        pow_state.last_verified_block = block;

        AnchorState {
            version: ANCHOR_STATE_VERSION,
            magic: [0u8; 4].into(),
            chain_view: ChainViewState {
                pow_state,
                history_accumulator: AsmHistoryAccumulatorState::new(u64::from(block.height())),
            },
            sections: Default::default(),
        }
    }

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

    #[test]
    fn every_pointerless_state_store_is_rejected() {
        let (db, _dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        let low = make_commitment(7, 0xaa);
        let high = make_commitment(9, 0xbb);

        // Simulate the layout written by a release before the active-tip
        // metadata existed.
        store
            .states
            .insert(encode_block_commitment(&low), state_at(low).as_ssz_bytes())
            .unwrap();

        assert!(
            store
                .get_latest()
                .unwrap_err()
                .to_string()
                .contains("states but no active-tip record"),
            "a snapshot write must never infer activation",
        );

        store
            .states
            .insert(
                encode_block_commitment(&high),
                state_at(high).as_ssz_bytes(),
            )
            .unwrap();
        let error = store.get_latest().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("states but no active-tip record")
        );
        assert!(
            store
                .delete(&low)
                .unwrap_err()
                .to_string()
                .contains("states but no active-tip record"),
            "maintenance must not make an ambiguous legacy store look valid",
        );
    }

    #[test]
    fn malformed_rows_are_rejected_even_with_an_active_tip() {
        let (db, _dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        let active = make_commitment(1, 0xaa);
        store.commit(&state_at(active)).unwrap();
        store.states.insert(b"unknown", b"value").unwrap();

        assert!(
            store
                .get_latest()
                .unwrap_err()
                .to_string()
                .contains("unrecognized key")
        );
    }

    #[test]
    fn latest_is_the_active_tip_not_the_highest_retained_orphan() {
        let (db, dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        let orphan = make_commitment(9, 0xaa);
        let shorter_reorg_tip = make_commitment(7, 0xbb);

        store.commit(&state_at(shorter_reorg_tip)).unwrap();
        store.put(&state_at(orphan)).unwrap();

        assert_eq!(
            store.get_latest().unwrap().unwrap().0,
            shorter_reorg_tip,
            "the last adopted branch survives restart even when an orphan is higher",
        );
        assert!(store.get(&orphan).unwrap().is_some(), "orphan is retained");
        assert_eq!(store.list().unwrap(), vec![shorter_reorg_tip, orphan]);

        db.flush().unwrap();
        drop(store);
        drop(db);

        let reopened_db = sled::open(dir.path()).unwrap();
        let reopened = SledAsmStateDb::open(&reopened_db).unwrap();
        assert_eq!(
            reopened.get_latest().unwrap().unwrap().0,
            shorter_reorg_tip,
            "the active-tip pointer is durable",
        );
    }

    /// The row key and the commitment embedded in its state are independent
    /// bytes on disk. Corruption must not let either a direct lookup or the
    /// active-tip lookup return a state for a different block.
    #[test]
    fn state_rows_are_bound_to_their_commitment_keys() {
        let (db, _dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        let selected = make_commitment(7, 0xaa);
        let embedded = make_commitment(7, 0xbb);

        store.commit(&state_at(selected)).unwrap();
        store
            .states
            .insert(
                encode_block_commitment(&selected),
                state_at(embedded).as_ssz_bytes(),
            )
            .unwrap();

        let direct = store.get(&selected).unwrap_err().to_string();
        assert!(direct.contains(&selected.to_string()));
        assert!(direct.contains(&embedded.to_string()));

        let latest = store.get_latest().unwrap_err().to_string();
        assert!(latest.contains(&selected.to_string()));
        assert!(latest.contains(&embedded.to_string()));
    }

    #[test]
    fn deleting_the_active_tip_does_not_select_a_retained_branch() {
        let (db, _dir) = test_db();
        let store = SledAsmStateDb::open(&db).unwrap();
        let retained = make_commitment(8, 0xaa);
        let active = make_commitment(7, 0xbb);

        store.put(&state_at(retained)).unwrap();
        store.commit(&state_at(active)).unwrap();
        assert!(store.delete(&active).unwrap());

        assert!(store.get_latest().unwrap().is_none());
        assert!(store.get(&retained).unwrap().is_some());
    }
}
