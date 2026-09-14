//! [`MohoStateDb`] implementation backed by sled.

use anyhow::Context;
use moho_types::MohoState;
use sled::transaction::{ConflictableTransactionError, TransactionError, TransactionalTree};
use ssz::{Decode, Encode};
use strata_identifiers::L1BlockCommitment;

use super::{decode_moho_key, encode_moho_key};
use crate::MohoStateDb;

/// Metadata key containing the full commitment of the worker's active tip.
/// Valid Moho-state keys are always 36 bytes, so this cannot collide with one.
const ACTIVE_TIP_KEY: &[u8] = b"\0";

/// Durable marker for a cross-tree rollback that has not committed yet.
const REBASE_JOURNAL_KEY: &[u8] = b"\x01";

/// Monotonic generation for consistent state/export read snapshots.
const VIEW_GENERATION_KEY: &[u8] = b"\x02";

/// Explicit marker left when maintenance removes the active state.
const NO_ACTIVE_TIP: &[u8] = b"none";

/// Sled-backed store for [`MohoState`] snapshots keyed by [`L1BlockCommitment`].
///
/// Values are SSZ-encoded; keys use big-endian height encoding so lexicographic
/// range scans match block-height ordering.
#[derive(Debug, Clone)]
pub struct SledMohoStateDb {
    moho_states: sled::Tree,
}

impl SledMohoStateDb {
    /// Tree name the store occupies within its sled database.
    const TREE_NAME: &'static str = "moho_states";

    /// Opens the Moho-state tree on an already-open sled database.
    ///
    /// Callers open the [`sled::Db`] themselves so multiple handles can share
    /// the same on-disk directory; sled does not allow opening the same path
    /// twice in a process.
    pub fn open(db: &sled::Db) -> Result<Self, sled::Error> {
        Ok(Self {
            moho_states: db.open_tree(Self::TREE_NAME)?,
        })
    }

    /// Whether `db` already contains the Moho-state tree.
    ///
    /// [`Self::open`] creates a missing tree as a side effect. Callers that
    /// must not mutate a database they did not create — offline tooling
    /// probing an operator-supplied path — check this before opening.
    pub fn exists_in(db: &sled::Db) -> bool {
        db.tree_names()
            .iter()
            .any(|name| name.as_ref() == Self::TREE_NAME.as_bytes())
    }

    /// Synchronous variant of [`MohoStateDb::store_moho_state`]. Stores a
    /// block-addressable snapshot without selecting it as the active tip.
    pub fn store(&self, l1ref: L1BlockCommitment, state: MohoState) -> Result<(), sled::Error> {
        let key = encode_moho_key(&l1ref);
        self.moho_states.insert(key, state.as_ssz_bytes())?;
        Ok(())
    }

    /// Atomically stores `state` and selects `l1ref` as the durable active tip.
    ///
    /// Worker commits use this method. Keeping it separate from [`Self::store`]
    /// prevents an offline historical-state write from changing restart state.
    pub fn commit(&self, l1ref: L1BlockCommitment, state: MohoState) -> Result<(), sled::Error> {
        let key = encode_moho_key(&l1ref);
        let state_bytes = state.as_ssz_bytes();
        self.moho_states
            .transaction(|states| {
                if let Some(base) = read_pending_rebase_transactional(states)? {
                    return Err(ConflictableTransactionError::Abort(invalid_store(format!(
                        "Moho state/export rebase to {base} is still in progress"
                    ))));
                }

                let generation = read_generation_transactional(states)?;
                let next =
                    next_generation(generation).map_err(ConflictableTransactionError::Abort)?;
                states.insert(key.to_vec(), state_bytes.clone())?;
                states.insert(ACTIVE_TIP_KEY.to_vec(), key.to_vec())?;
                states.insert(VIEW_GENERATION_KEY.to_vec(), next.to_vec())?;
                Ok(())
            })
            .map_err(transaction_error)
    }

    /// Synchronous variant of [`MohoStateDb::get_moho_state`]. See [`Self::store`].
    pub fn get(&self, l1ref: L1BlockCommitment) -> Result<Option<MohoState>, sled::Error> {
        self.moho_states
            .get(encode_moho_key(&l1ref))?
            .map(|bytes| decode_state(&bytes))
            .transpose()
    }

    /// Reads one state only when no cross-tree rebase is in progress.
    ///
    /// The generation is checked on both sides of the read so a rebase that
    /// starts and finishes concurrently is detected rather than exposing a
    /// state as part of a mixed state/export view.
    pub fn get_ready(&self, l1ref: L1BlockCommitment) -> Result<Option<MohoState>, sled::Error> {
        let before = self.view_generation()?;
        let state = self.get(l1ref)?;
        let after = self.view_generation()?;
        if before != after {
            return Err(invalid_store(format!(
                "Moho view changed during read: generation {before} -> {after}"
            )));
        }
        Ok(state)
    }

    /// Returns the current ready-view generation, rejecting an open rebase.
    pub fn view_generation(&self) -> Result<u64, sled::Error> {
        if let Some(base) = read_pending_rebase(&self.moho_states)? {
            return Err(invalid_store(format!(
                "Moho state/export rebase to {base} is still in progress"
            )));
        }
        read_generation(&self.moho_states)
    }

    /// Durably gates readers before a cross-tree rebase mutates export rows.
    pub fn begin_rebase(&self, base: L1BlockCommitment) -> Result<(), sled::Error> {
        validate_tree_keys(&self.moho_states)?;
        let state_key = encode_moho_key(&base);
        self.moho_states
            .transaction(|states| {
                if states.get(state_key)?.is_none() {
                    return Err(ConflictableTransactionError::Abort(invalid_store(format!(
                        "cannot begin Moho rebase: base {base} has no stored state"
                    ))));
                }

                let generation = read_generation_transactional(states)?;
                next_generation(generation).map_err(ConflictableTransactionError::Abort)?;

                if let Some(pending) = read_pending_rebase_transactional(states)? {
                    return if pending == base {
                        Ok(())
                    } else {
                        Err(ConflictableTransactionError::Abort(invalid_store(format!(
                            "Moho rebase to {pending} is already in progress; cannot begin {base}"
                        ))))
                    };
                }

                states.insert(REBASE_JOURNAL_KEY.to_vec(), state_key.to_vec())?;
                states.flush();
                Ok(())
            })
            .map_err(transaction_error)
    }

    /// Validates the retained export prefix, then commits the journaled base as
    /// active and opens the read gate atomically.
    pub fn finish_rebase(
        &self,
        base: L1BlockCommitment,
        export_entries: &super::SledExportEntriesDb,
    ) -> Result<(), sled::Error> {
        validate_tree_keys(&self.moho_states)?;
        let state_key = encode_moho_key(&base);
        let state = self.get(base)?.ok_or_else(|| {
            invalid_store(format!(
                "cannot finish Moho rebase: base {base} has no stored state"
            ))
        })?;
        export_entries
            .validate_export_state(state.export_state())
            .map_err(|error| {
                invalid_store(format!(
                    "export projection does not match Moho rebase base {base}: {error:#}"
                ))
            })?;
        let validated_state = state.as_ssz_bytes();

        self.moho_states
            .transaction(|states| {
                let pending = read_pending_rebase_transactional(states)?.ok_or_else(|| {
                    ConflictableTransactionError::Abort(invalid_store(format!(
                        "no Moho rebase is pending for base {base}"
                    )))
                })?;
                if pending != base {
                    return Err(ConflictableTransactionError::Abort(invalid_store(format!(
                        "Moho rebase journal targets {pending}, not requested base {base}"
                    ))));
                }

                match states.get(state_key)? {
                    Some(current) if current.as_ref() == validated_state.as_slice() => {}
                    Some(_) => {
                        return Err(ConflictableTransactionError::Abort(invalid_store(format!(
                            "cannot finish Moho rebase: base state {base} changed during validation"
                        ))));
                    }
                    None => {
                        return Err(ConflictableTransactionError::Abort(invalid_store(format!(
                            "cannot finish Moho rebase: base {base} has no stored state"
                        ))));
                    }
                }

                let generation = read_generation_transactional(states)?;
                let next =
                    next_generation(generation).map_err(ConflictableTransactionError::Abort)?;
                states.insert(ACTIVE_TIP_KEY.to_vec(), state_key.to_vec())?;
                states.insert(VIEW_GENERATION_KEY.to_vec(), next.to_vec())?;
                states.remove(REBASE_JOURNAL_KEY.to_vec())?;
                states.flush();
                Ok(())
            })
            .map_err(transaction_error)
    }

    /// Completes an interrupted cross-tree rebase idempotently.
    pub fn recover_rebase(
        &self,
        export_entries: &super::SledExportEntriesDb,
    ) -> anyhow::Result<bool> {
        let Some(base) = self.pending_rebase()? else {
            return Ok(false);
        };
        let state_key = encode_moho_key(&base);
        if !self.moho_states.contains_key(state_key)? {
            anyhow::bail!("cannot recover Moho rebase: base {base} has no stored state");
        }
        // Validate every state-tree precondition before touching the export
        // projection. In particular, an invalid or exhausted generation must
        // not turn a corrupt journal into a destructive partial recovery.
        next_generation(read_generation(&self.moho_states)?)?;

        if let Some(first_suffix_height) = base.height().checked_add(1) {
            export_entries
                .prune_from(first_suffix_height)
                .with_context(|| format!("recover export-entry suffix above Moho base {base}"))?;
        }
        self.finish_rebase(base, export_entries)
            .with_context(|| format!("finish recovered Moho rebase to {base}"))?;
        Ok(true)
    }

    /// Returns the journaled base without requiring the read view to be ready.
    pub fn pending_rebase(&self) -> Result<Option<L1BlockCommitment>, sled::Error> {
        validate_tree_keys(&self.moho_states)?;
        read_pending_rebase(&self.moho_states)
    }

    /// Returns the durable active Moho state and its block commitment.
    ///
    /// Retained orphan states can be higher than the active tip after a shorter
    /// reorg, so key ordering is not a chain-selection rule. Under the fresh-store
    /// cutover, any state row without an active record is rejected instead of
    /// inferring activation from either cardinality or key ordering.
    pub fn get_latest(&self) -> Result<Option<(L1BlockCommitment, MohoState)>, sled::Error> {
        validate_tree_keys(&self.moho_states)?;
        self.view_generation()?;
        let state_key = match self.moho_states.get(ACTIVE_TIP_KEY)? {
            Some(marker) if marker.as_ref() == NO_ACTIVE_TIP => return Ok(None),
            Some(key) if is_state_key(&key) => key,
            Some(key) => {
                return Err(invalid_store(format!(
                    "invalid Moho active-tip key length: expected {}, got {}",
                    super::ENCODED_L1_COMMITMENT_SIZE,
                    key.len(),
                )));
            }
            None if has_state_rows(&self.moho_states)? => {
                return Err(invalid_store(
                    "Moho state store has states but no active-tip record".to_owned(),
                ));
            }
            None => return Ok(None),
        };
        let value = self.moho_states.get(&state_key)?.ok_or_else(|| {
            invalid_store(format!(
                "Moho active tip {} has no stored state",
                decode_moho_key(&state_key),
            ))
        })?;
        let commitment = decode_moho_key(&state_key);
        let state = decode_state(&value)?;
        Ok(Some((commitment, state)))
    }

    /// Synchronous variant of [`MohoStateDb::prune`]. See [`Self::store`].
    pub fn prune_before(&self, before_height: u32) -> Result<(), sled::Error> {
        let upper: &[u8] = &before_height.to_be_bytes();
        let active = self.active_tip_key()?;
        let mut batch = sled::Batch::default();
        for entry in self.moho_states.range(..upper) {
            let (key, _) = entry?;
            if is_state_key(&key) {
                batch.remove(key);
            }
        }
        if active.is_some_and(|key| decode_moho_key(&key).height() < before_height) {
            batch.insert(ACTIVE_TIP_KEY, NO_ACTIVE_TIP);
        }
        self.moho_states.apply_batch(batch)?;
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
        let active = self.active_tip_key()?;
        let mut batch = sled::Batch::default();
        for entry in self.moho_states.range(lower..) {
            let (key, _) = entry?;
            if is_state_key(&key) {
                batch.remove(key);
            }
        }
        if active.is_some_and(|key| decode_moho_key(&key).height() > after_height) {
            batch.insert(ACTIVE_TIP_KEY, NO_ACTIVE_TIP);
        }
        self.moho_states.apply_batch(batch)?;
        Ok(())
    }

    /// Removes the Moho state for `l1ref`, returning whether one was present.
    ///
    /// For inspection tooling; the worker never deletes individual states.
    pub fn delete(&self, l1ref: &L1BlockCommitment) -> Result<bool, sled::Error> {
        let key = encode_moho_key(l1ref);
        let was_active = self.active_tip_key()?.as_deref() == Some(key.as_slice());
        let existed = self.moho_states.contains_key(key)?;
        if !existed {
            return Ok(false);
        }

        let mut batch = sled::Batch::default();
        batch.remove(key.as_slice());
        if was_active {
            batch.insert(ACTIVE_TIP_KEY, NO_ACTIVE_TIP);
        }
        self.moho_states.apply_batch(batch)?;
        Ok(true)
    }

    /// Returns every stored Moho-state key, in ascending height order.
    ///
    /// For inspection tooling: keys are decoded from the tree without reading
    /// the (large) values.
    pub fn list(&self) -> Result<Vec<L1BlockCommitment>, sled::Error> {
        validate_tree_keys(&self.moho_states)?;
        self.moho_states
            .iter()
            .keys()
            .filter_map(|key| match key {
                Ok(key) if is_state_key(&key) => Some(Ok(decode_moho_key(&key))),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    fn active_tip_key(&self) -> Result<Option<sled::IVec>, sled::Error> {
        validate_tree_keys(&self.moho_states)?;
        self.view_generation()?;
        match self.moho_states.get(ACTIVE_TIP_KEY)? {
            Some(marker) if marker.as_ref() == NO_ACTIVE_TIP => Ok(None),
            Some(key) if is_state_key(&key) => Ok(Some(key)),
            Some(key) => Err(invalid_store(format!(
                "invalid Moho active-tip key length: expected {}, got {}",
                super::ENCODED_L1_COMMITMENT_SIZE,
                key.len(),
            ))),
            None if has_state_rows(&self.moho_states)? => Err(invalid_store(
                "Moho state store has states but no active-tip record".to_owned(),
            )),
            None => Ok(None),
        }
    }
}

fn is_state_key(key: &[u8]) -> bool {
    key.len() == super::ENCODED_L1_COMMITMENT_SIZE
}

fn decode_state(bytes: &[u8]) -> Result<MohoState, sled::Error> {
    MohoState::from_ssz_bytes(bytes)
        .map_err(|error| invalid_store(format!("invalid stored Moho state SSZ: {error:?}")))
}

fn invalid_store(message: String) -> sled::Error {
    sled::Error::Unsupported(message)
}

fn validate_tree_keys(states: &sled::Tree) -> Result<(), sled::Error> {
    for entry in states.iter().keys() {
        let key = entry?;
        let metadata = matches!(
            key.as_ref(),
            ACTIVE_TIP_KEY | REBASE_JOURNAL_KEY | VIEW_GENERATION_KEY
        );
        if !metadata && !is_state_key(&key) {
            return Err(invalid_store(format!(
                "Moho state store has an unrecognized key of {} bytes",
                key.len(),
            )));
        }
    }
    Ok(())
}

fn has_state_rows(states: &sled::Tree) -> Result<bool, sled::Error> {
    for entry in states.iter().keys() {
        if is_state_key(&entry?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_generation(states: &sled::Tree) -> Result<u64, sled::Error> {
    let bytes = states.get(VIEW_GENERATION_KEY)?;
    decode_generation(bytes.as_deref())
}

fn read_generation_transactional(
    states: &TransactionalTree,
) -> Result<u64, ConflictableTransactionError<sled::Error>> {
    let bytes = states.get(VIEW_GENERATION_KEY)?;
    decode_generation(bytes.as_deref()).map_err(ConflictableTransactionError::Abort)
}

fn decode_generation(bytes: Option<&[u8]>) -> Result<u64, sled::Error> {
    let Some(bytes) = bytes else {
        return Ok(0);
    };
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| {
        invalid_store(format!(
            "invalid Moho view-generation length: expected 8, got {}",
            bytes.len(),
        ))
    })?;
    Ok(u64::from_be_bytes(encoded))
}

fn read_pending_rebase(states: &sled::Tree) -> Result<Option<L1BlockCommitment>, sled::Error> {
    let key = states.get(REBASE_JOURNAL_KEY)?;
    decode_pending_rebase(key.as_deref())
}

fn read_pending_rebase_transactional(
    states: &TransactionalTree,
) -> Result<Option<L1BlockCommitment>, ConflictableTransactionError<sled::Error>> {
    let key = states.get(REBASE_JOURNAL_KEY)?;
    decode_pending_rebase(key.as_deref()).map_err(ConflictableTransactionError::Abort)
}

fn decode_pending_rebase(key: Option<&[u8]>) -> Result<Option<L1BlockCommitment>, sled::Error> {
    key.map(|key| {
        if !is_state_key(key) {
            return Err(invalid_store(format!(
                "invalid Moho rebase journal key length: expected {}, got {}",
                super::ENCODED_L1_COMMITMENT_SIZE,
                key.len(),
            )));
        }
        Ok(decode_moho_key(key))
    })
    .transpose()
}

fn next_generation(current: u64) -> Result<[u8; 8], sled::Error> {
    current
        .checked_add(1)
        .map(u64::to_be_bytes)
        .ok_or_else(|| invalid_store("Moho view generation overflow".to_owned()))
}

fn transaction_error(error: TransactionError<sled::Error>) -> sled::Error {
    match error {
        TransactionError::Abort(error) | TransactionError::Storage(error) => error,
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
        self.get_ready(l1ref)
    }

    async fn view_generation(&self) -> Result<u64, Self::Error> {
        self.view_generation()
    }

    async fn get_latest_moho_state(
        &self,
    ) -> Result<Option<(L1BlockCommitment, MohoState)>, Self::Error> {
        self.get_latest()
    }

    async fn prune(&self, before_height: u32) -> Result<(), Self::Error> {
        self.prune_before(before_height)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

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

    fn moho_state_with_export(inner: u8, container: u8, entry: [u8; 32]) -> MohoState {
        let mut export_state = ExportState::new(vec![]).unwrap();
        export_state.add_entry(container, entry).unwrap();
        MohoState::new(
            InnerStateCommitment::from([inner; 32]),
            PredicateKey::always_accept(),
            export_state,
        )
    }

    #[test]
    fn get_latest_on_empty_returns_none() {
        let (db, _dir) = temp_moho_db();
        assert!(db.get_latest().unwrap().is_none());
    }

    // `exists_in` must not itself create the tree — it is the guard callers
    // use to avoid `open`'s create-on-miss side effect.
    #[test]
    fn exists_in_reports_tree_presence_without_creating_it() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let db = sled::open(dir.path()).expect("failed to open sled db");

        assert!(!SledMohoStateDb::exists_in(&db));
        assert!(!SledMohoStateDb::exists_in(&db)); // probing twice creates nothing

        SledMohoStateDb::open(&db).expect("failed to open moho state tree");
        assert!(SledMohoStateDb::exists_in(&db));
    }

    #[test]
    fn latest_is_the_active_tip_not_the_highest_retained_orphan() {
        let (db, dir) = temp_moho_db();
        let shorter_reorg_tip = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let orphan = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x22; 32])));

        db.commit(shorter_reorg_tip, moho_state(0xaa)).unwrap();
        db.store(orphan, moho_state(0xbb)).unwrap();

        let (blk, state) = db.get_latest().unwrap().unwrap();
        assert_eq!(blk, shorter_reorg_tip);
        assert_eq!(state, moho_state(0xaa));
        assert!(db.get(orphan).unwrap().is_some(), "orphan is retained");

        db.moho_states.flush().unwrap();
        drop(db);

        let reopened_db = sled::open(dir.path()).unwrap();
        let reopened = SledMohoStateDb::open(&reopened_db).unwrap();
        assert_eq!(
            reopened.get_latest().unwrap().unwrap().0,
            shorter_reorg_tip,
            "the active-tip pointer survives a real sled close and reopen",
        );
    }

    #[test]
    fn every_pointerless_state_store_is_rejected() {
        let (db, _dir) = temp_moho_db();
        let first = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let second = L1BlockCommitment::new(8, L1BlockId::from(Buf32::from([0x22; 32])));

        db.moho_states
            .insert(encode_moho_key(&first), moho_state(0xaa).as_ssz_bytes())
            .unwrap();
        assert!(
            db.get_latest()
                .unwrap_err()
                .to_string()
                .contains("states but no active-tip record"),
            "a snapshot write must never infer activation",
        );

        db.moho_states
            .insert(encode_moho_key(&second), moho_state(0xbb).as_ssz_bytes())
            .unwrap();
        let error = db.get_latest().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("states but no active-tip record")
        );
        assert!(
            db.delete(&first)
                .unwrap_err()
                .to_string()
                .contains("states but no active-tip record"),
            "maintenance must not make an ambiguous legacy store look valid",
        );
    }

    #[test]
    fn malformed_rows_are_rejected_even_with_an_active_tip() {
        let (db, _dir) = temp_moho_db();
        let active = L1BlockCommitment::new(1, L1BlockId::from(Buf32::from([0xaa; 32])));
        db.commit(active, moho_state(0xaa)).unwrap();
        db.moho_states.insert(b"unknown", b"value").unwrap();

        assert!(
            db.get_latest()
                .unwrap_err()
                .to_string()
                .contains("unrecognized key")
        );
    }

    #[test]
    fn concurrent_commits_preserve_every_generation_increment() {
        const WRITERS: usize = 16;

        let (db, _dir) = temp_moho_db();
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles = (0..WRITERS)
            .map(|writer| {
                let db = db.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let byte = u8::try_from(writer + 1).unwrap();
                    let commitment = L1BlockCommitment::new(
                        u32::try_from(writer + 1).unwrap(),
                        L1BlockId::from(Buf32::from([byte; 32])),
                    );
                    barrier.wait();
                    db.commit(commitment, moho_state(byte)).unwrap();
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(db.view_generation().unwrap(), WRITERS as u64);
        assert_eq!(db.list().unwrap().len(), WRITERS);
    }

    #[test]
    fn commit_cannot_bypass_an_open_rebase_journal() {
        let (db, _dir) = temp_moho_db();
        let base = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x71; 32])));
        let next = L1BlockCommitment::new(8, L1BlockId::from(Buf32::from([0x81; 32])));
        db.commit(base, moho_state(0x71)).unwrap();
        let generation = db.view_generation().unwrap();

        db.begin_rebase(base).unwrap();
        let error = db.commit(next, moho_state(0x81)).unwrap_err();

        assert!(error.to_string().contains("still in progress"));
        assert_eq!(db.pending_rebase().unwrap(), Some(base));
        assert!(db.get(next).unwrap().is_none());
        assert_eq!(read_generation(&db.moho_states).unwrap(), generation);
    }

    fn assert_interrupted_rebase_recovers(prune_before_restart: bool) {
        let dir = tempfile::tempdir().unwrap();
        let sled_db = sled::open(dir.path()).unwrap();
        let states = SledMohoStateDb::open(&sled_db).unwrap();
        let exports = crate::SledExportEntriesDb::open(&sled_db).unwrap();
        let base = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x71; 32])));
        let old_tip = L1BlockCommitment::new(9, L1BlockId::from(Buf32::from([0x91; 32])));

        exports.append(0, 7, vec![[0x71; 32]]).unwrap();
        states
            .commit(base, moho_state_with_export(0x71, 0, [0x71; 32]))
            .unwrap();
        exports.append(0, 8, vec![[0x81; 32]]).unwrap();
        exports.append(0, 9, vec![[0x91; 32]]).unwrap();
        states.commit(old_tip, moho_state(0x91)).unwrap();
        let generation_before = states.view_generation().unwrap();

        states.begin_rebase(base).unwrap();
        assert_eq!(states.pending_rebase().unwrap(), Some(base));
        assert!(
            states
                .get_latest()
                .unwrap_err()
                .to_string()
                .contains("still in progress")
        );
        assert!(
            states
                .get_ready(base)
                .unwrap_err()
                .to_string()
                .contains("still in progress")
        );

        if prune_before_restart {
            exports.prune_from(8).unwrap();
        }
        sled_db.flush().unwrap();
        drop(states);
        drop(exports);
        drop(sled_db);

        let reopened_db = sled::open(dir.path()).unwrap();
        let reopened_states = SledMohoStateDb::open(&reopened_db).unwrap();
        let reopened_exports = crate::SledExportEntriesDb::open(&reopened_db).unwrap();
        assert!(reopened_states.recover_rebase(&reopened_exports).unwrap());

        assert_eq!(reopened_states.pending_rebase().unwrap(), None);
        assert_eq!(reopened_states.get_latest().unwrap().unwrap().0, base);
        assert_eq!(
            reopened_states.view_generation().unwrap(),
            generation_before + 1
        );
        assert_eq!(reopened_exports.num_entries(0).unwrap(), 1);
        assert!(reopened_states.get_ready(base).unwrap().is_some());
    }

    #[test]
    fn startup_recovers_rebase_interrupted_before_export_prune() {
        assert_interrupted_rebase_recovers(false);
    }

    #[test]
    fn startup_recovers_rebase_interrupted_after_export_prune() {
        assert_interrupted_rebase_recovers(true);
    }

    #[test]
    fn recovery_keeps_the_read_gate_closed_when_the_export_prefix_is_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let sled_db = sled::open(dir.path()).unwrap();
        let states = SledMohoStateDb::open(&sled_db).unwrap();
        let exports = crate::SledExportEntriesDb::open(&sled_db).unwrap();
        let base = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x71; 32])));
        states
            .commit(base, moho_state_with_export(0x71, 0, [0x71; 32]))
            .unwrap();
        exports.append(0, 7, vec![[0x72; 32]]).unwrap();
        let generation = states.view_generation().unwrap();
        states.begin_rebase(base).unwrap();

        let error = states.recover_rebase(&exports).unwrap_err();

        assert!(format!("{error:#}").contains("does not match the Moho state"));
        assert_eq!(states.pending_rebase().unwrap(), Some(base));
        assert_eq!(read_generation(&states.moho_states).unwrap(), generation);
        assert!(
            states
                .get_latest()
                .unwrap_err()
                .to_string()
                .contains("still in progress")
        );
    }

    #[test]
    fn recovery_does_not_prune_when_the_journal_base_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let sled_db = sled::open(dir.path()).unwrap();
        let states = SledMohoStateDb::open(&sled_db).unwrap();
        let exports = crate::SledExportEntriesDb::open(&sled_db).unwrap();
        let active = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x71; 32])));
        let missing_base = L1BlockCommitment::new(8, L1BlockId::from(Buf32::from([0x81; 32])));

        states.commit(active, moho_state(0x71)).unwrap();
        exports.append(0, 7, vec![[0x71; 32]]).unwrap();
        exports.append(0, 8, vec![[0x81; 32]]).unwrap();
        states
            .moho_states
            .insert(
                REBASE_JOURNAL_KEY,
                encode_moho_key(&missing_base).as_slice(),
            )
            .unwrap();

        let error = states.recover_rebase(&exports).unwrap_err();
        assert!(error.to_string().contains("has no stored state"));
        assert_eq!(exports.num_entries(0).unwrap(), 2);
        assert_eq!(states.pending_rebase().unwrap(), Some(missing_base));
    }

    #[test]
    fn list_returns_keys_in_height_order() {
        let (db, _dir) = temp_moho_db();
        let low = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let high = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x22; 32])));

        assert!(db.list().unwrap().is_empty());
        db.commit(high, moho_state(0xbb)).unwrap();
        db.commit(low, moho_state(0xaa)).unwrap();

        // Keys come back in ascending height order regardless of insertion order.
        assert_eq!(db.list().unwrap(), vec![low, high]);
    }

    #[test]
    fn delete_removes_only_the_targeted_key() {
        let (db, _dir) = temp_moho_db();
        let a = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x11; 32])));
        let b = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x22; 32])));
        db.commit(a, moho_state(0xaa)).unwrap();
        db.commit(b, moho_state(0xbb)).unwrap();

        assert!(db.delete(&a).unwrap());
        assert!(db.get(a).unwrap().is_none());
        assert!(db.get(b).unwrap().is_some());
        // Deleting an absent key reports no removal.
        assert!(!db.delete(&a).unwrap());
    }

    #[test]
    fn deleting_the_active_tip_does_not_select_a_retained_branch() {
        let (db, _dir) = temp_moho_db();
        let retained = L1BlockCommitment::new(42, L1BlockId::from(Buf32::from([0x11; 32])));
        let active = L1BlockCommitment::new(7, L1BlockId::from(Buf32::from([0x22; 32])));
        db.store(retained, moho_state(0xaa)).unwrap();
        db.commit(active, moho_state(0xbb)).unwrap();

        assert!(db.delete(&active).unwrap());
        assert!(db.get_latest().unwrap().is_none());
        assert!(db.get(retained).unwrap().is_some());
    }

    #[test]
    fn prune_after_removes_entries_above_height() {
        let (db, _dir) = temp_moho_db();
        let keep = L1BlockCommitment::new(10, L1BlockId::from(Buf32::from([0x11; 32])));
        let boundary = L1BlockCommitment::new(20, L1BlockId::from(Buf32::from([0x22; 32])));
        let drop = L1BlockCommitment::new(21, L1BlockId::from(Buf32::from([0x33; 32])));
        db.commit(keep, moho_state(0xaa)).unwrap();
        db.commit(boundary, moho_state(0xbb)).unwrap();
        db.commit(drop, moho_state(0xcc)).unwrap();

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
                    db.commit(*c, state.clone()).unwrap();
                }
                for (c, state) in &above_entries {
                    db.commit(*c, state.clone()).unwrap();
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
