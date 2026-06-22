//! Bridge Operator Management
//!
//! This module contains types and tables for managing bridge operators

use std::cmp;

use bitcoin::{ScriptBuf, secp256k1::SECP256K1};
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_asm_common::{
    logging::{debug, info, warn},
    sorted_vec::SortedVec,
};
use strata_asm_proto_bridge_v1_types::{OperatorBitmap, OperatorIdx};
use strata_btc_types::{BitcoinScriptBuf, BitcoinXOnlyPublicKey};
use strata_crypto::{EvenPublicKey, aggregate_schnorr_keys};
use strata_identifiers::Buf32;

/// Bridge operator entry containing identification and cryptographic keys.
///
/// Each operator registered in the bridge has:
///
/// - **`idx`** - Unique identifier used to reference the operator globally
/// - **`musig2_pk`** - Public key for Bitcoin transaction signatures (MuSig2 compatible)
///
/// # Bitcoin Compatibility
///
/// The `musig2_pk` follows [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#design)
/// standard, corresponding to a [`PublicKey`](bitcoin::secp256k1::PublicKey) with even parity
/// for compatibility with Bitcoin's Taproot and MuSig2 implementations.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encode, Decode)]
pub struct OperatorEntry {
    /// Global operator index.
    idx: OperatorIdx,

    /// Public key used to compute MuSig2 public key from a set of operators.
    musig2_pk: EvenPublicKey,
}

impl PartialOrd for OperatorEntry {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OperatorEntry {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.idx().cmp(&other.idx())
    }
}

impl OperatorEntry {
    /// Returns the unique operator index.
    ///
    /// # Returns
    ///
    /// The [`OperatorIdx`] that uniquely identifies this operator.
    pub fn idx(&self) -> OperatorIdx {
        self.idx
    }

    /// Returns the MuSig2 public key for Bitcoin transactions.
    ///
    /// This key is used in MuSig2 aggregation for Bitcoin transaction signatures
    /// and follows BIP 340 standard for Taproot compatibility.
    ///
    /// # Returns
    ///
    /// Reference to the MuSig2 public key as [`EvenPublicKey`].
    pub fn musig2_pk(&self) -> &EvenPublicKey {
        &self.musig2_pk
    }
}

/// Builds a key-path-only P2TR script for the provided aggregated operator key.
pub(crate) fn build_nn_script(agg_key: &BitcoinXOnlyPublicKey) -> BitcoinScriptBuf {
    // A key-path-only P2TR script is a fixed 34 bytes, always within `MAX_SCRIPT_SIZE`.
    BitcoinScriptBuf::try_from(ScriptBuf::new_p2tr(
        SECP256K1,
        agg_key.to_xonly_public_key(),
        None,
    ))
    .expect("p2tr script within size bound")
}

/// Position of a `HistoricalNnScript` within `NnScriptHistory`.
///
/// Because the history is append-only (see `NnScriptHistory`), an entry's position is a stable
/// handle for its lifetime. Deposits store such an index to bind their notary set to a recognized
/// historical N/N configuration instead of duplicating the operator bitmap.
pub type NnScriptIdx = u32;

/// A historical N/N multisig configuration of the bridge.
///
/// Pairs the P2TR script that represented the bridge for a given operator set with the bitmap of
/// operators that were active in that set. Storing the membership alongside the script lets
/// validation recover which operators backed a historical configuration without recomputing it.
///
/// # Coherence Invariant
///
/// `script` **MUST** be the key-path-only P2TR derived from the MuSig2 aggregation of exactly the
/// operators set in `operators`. The two fields are not independent: validation trusts that
/// resolving the notary set from `operators` and matching stake connectors against `script` refer
/// to the same operator set, so a mismatch silently breaks the binding this type exists to record.
///
/// Construction does **not** verify this — the constructor cannot, since it does not hold the
/// operator public keys needed to recompute the aggregation. In-crate, coherence is guaranteed
/// because the only production path that builds an entry is `OperatorTable::record_nn_script`,
/// which derives the script from the freshly aggregated key over the same bitmap it stores.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct HistoricalNnScript {
    /// Key-path-only P2TR script (merkle root = `None`) built from the aggregated public key of
    /// the operator set at this point in history.
    script: BitcoinScriptBuf,

    /// Bitmap of operators that were active in the N/N multisig when `script` was current.
    operators: OperatorBitmap,
}

impl HistoricalNnScript {
    /// Creates a configuration pairing a key-path-only P2TR `script` with its active `operators`.
    ///
    /// The caller **MUST** uphold the coherence invariant documented on [`HistoricalNnScript`]:
    /// `script` has to be the P2TR derived from the MuSig2 aggregation of exactly `operators`. This
    /// constructor performs no validation. Prefer `OperatorTable::record_nn_script`, which
    /// upholds the invariant by construction.
    pub(crate) fn new(script: BitcoinScriptBuf, operators: OperatorBitmap) -> Self {
        Self { script, operators }
    }

    /// Returns the key-path-only P2TR script for this configuration.
    pub fn script(&self) -> &ScriptBuf {
        self.script.inner()
    }

    /// Returns the bitmap of operators that were active in this configuration.
    pub fn operators(&self) -> &OperatorBitmap {
        &self.operators
    }
}

/// Append-only history of the bridge's N/N multisig configurations, oldest first.
///
/// A new entry is appended on every operator membership change, so the last entry always describes
/// the current operator set. Entries are **never removed or reordered**: this keeps each entry's
/// position (a [`NnScriptIdx`]) stable so deposits can reference the configuration they were locked
/// under without copying its bitmap. Validation also walks the history to recognize stake
/// connectors from previous operator sets.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct NnScriptHistory {
    /// Configurations in chronological order. Append-only; the last entry is the current set.
    scripts: Vec<HistoricalNnScript>,
}

impl NnScriptHistory {
    /// Creates an empty history. Only used during bootstrap, before the first set is recorded.
    pub(crate) fn new_empty() -> Self {
        Self {
            scripts: Vec::new(),
        }
    }

    /// Appends a configuration and returns its stable index.
    pub(crate) fn push(&mut self, entry: HistoricalNnScript) -> NnScriptIdx {
        self.scripts.push(entry);
        (self.scripts.len() - 1) as NnScriptIdx
    }

    /// Returns the configuration at `idx`, or `None` if it is out of range.
    pub fn get(&self, idx: NnScriptIdx) -> Option<&HistoricalNnScript> {
        self.scripts.get(idx as usize)
    }

    /// Returns the index of the current (most recent) configuration.
    ///
    /// # Panics
    ///
    /// Panics if the history is empty, which can only happen before bootstrap completes.
    pub fn current_index(&self) -> NnScriptIdx {
        assert!(
            !self.scripts.is_empty(),
            "N/N script history should never be empty"
        );
        (self.scripts.len() - 1) as NnScriptIdx
    }

    /// Returns the current (most recent) configuration.
    ///
    /// # Panics
    ///
    /// Panics if the history is empty, which can only happen before bootstrap completes.
    pub fn current(&self) -> &HistoricalNnScript {
        self.scripts
            .last()
            .expect("N/N script history should never be empty")
    }

    /// Returns an iterator over all configurations in chronological order.
    pub fn iter(&self) -> impl Iterator<Item = &HistoricalNnScript> {
        self.scripts.iter()
    }
}

#[cfg(test)]
impl NnScriptHistory {
    /// Builds a history with a single configuration holding `operators` (index 0).
    ///
    /// The script is derived from a placeholder key, since tests resolving a notary set only care
    /// about the recorded operator bitmap.
    pub(crate) fn single_for_test(operators: OperatorBitmap) -> Self {
        let placeholder_agg_key = BitcoinXOnlyPublicKey::new([1u8; 32].into()).unwrap();
        let mut history = Self::new_empty();
        history.push(HistoricalNnScript::new(
            build_nn_script(&placeholder_agg_key),
            operators,
        ));
        history
    }
}

/// Table for managing registered bridge operators.
///
/// This table maintains all registered operators with efficient lookup and insertion
/// operations. The table automatically assigns unique indices and maintains sorted
/// order for binary search efficiency.
///
/// # Ordering Invariant
///
/// The operators vector **MUST** remain sorted by operator index at all times.
/// This invariant enables O(log n) lookup operations via binary search.
///
/// # Index Management
///
/// The table uses `next_idx` to track and assign operator indices:
///
/// - Indices are assigned sequentially starting from 0
/// - Each new registration increments `next_idx`
/// - Indices are never reused, even after operator exits
///
/// **WARNING**: Since indices are never reused and `OperatorIdx` is `u32`, the table
/// can support at most `u32::MAX - 1` unique operator registrations over its entire
/// lifetime. Index `u32::MAX` is reserved as a sentinel for "no selected operator"
/// in the withdrawal assignment protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorTable {
    /// Next unassigned operator index for new registrations.
    next_idx: OperatorIdx,

    /// Vector of registered operators, sorted by operator index.
    ///
    /// **Invariant**: MUST be sorted by `OperatorEntry::idx` field.
    operators: SortedVec<OperatorEntry>,

    /// Aggregated public key derived from operator MuSig2 keys that are currently active in the
    /// N/N multisig.
    ///
    /// This key is computed by aggregating the MuSig2 public keys of only those operators active
    /// in the current N/N multisig (the bitmap stored in the last `historical_nn_scripts` entry),
    /// using the MuSig2 key aggregation protocol. It serves as the collective public key for
    /// multi-signature operations and is used for:
    ///
    /// - Generating deposit addresses for the bridge
    /// - Verifying multi-signatures from the current operator set
    /// - Representing the current N/N multisig set as a single cryptographic entity
    ///
    /// The key is automatically computed when the operator table is created or
    /// updated, ensuring it always reflects the current active multisig participants.
    agg_key: BitcoinXOnlyPublicKey,

    /// Append-only history of N/N multisig configurations across membership changes.
    ///
    /// Each entry stores the key-path-only P2TR script (merkle root = None) built from the
    /// aggregated public key of the operator set at that time, alongside the bitmap of operators
    /// active then. Storing the script avoids recomputing P2TR scripts during validation, and the
    /// stable per-entry index lets deposits reference their notary set (see [`NnScriptHistory`]).
    historical_nn_scripts: NnScriptHistory,
}

#[derive(Debug, Encode, Decode)]
struct OperatorTableSsz {
    next_idx: OperatorIdx,
    operators: Vec<OperatorEntry>,
    agg_key: BitcoinXOnlyPublicKey,
    historical_nn_scripts: NnScriptHistory,
}

impl From<&OperatorTable> for OperatorTableSsz {
    fn from(value: &OperatorTable) -> Self {
        Self {
            next_idx: value.next_idx,
            operators: value.operators.to_vec(),
            agg_key: value.agg_key,
            historical_nn_scripts: value.historical_nn_scripts.clone(),
        }
    }
}

impl SszEncode for OperatorTable {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        OperatorTableSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        OperatorTableSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for OperatorTable {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let payload = OperatorTableSsz::from_ssz_bytes(bytes)?;
        let operators = SortedVec::try_from(payload.operators).map_err(|_| {
            DecodeError::BytesInvalid("operator table entries must stay sorted".into())
        })?;
        Ok(Self {
            next_idx: payload.next_idx,
            operators,
            agg_key: payload.agg_key,
            historical_nn_scripts: payload.historical_nn_scripts,
        })
    }
}

impl OperatorTable {
    /// Bootstraps an operator table with an initial active operator set.
    ///
    /// Every provided key is added and marked active, skipping any duplicates. The aggregated
    /// MuSig2 key and the first N/N script are computed via the normal membership change flow so
    /// script history starts with this initial configuration.
    ///
    /// Indices are assigned sequentially starting from 0.
    ///
    /// # Parameters
    ///
    /// - `operators` - Initial set of [`EvenPublicKey`] MuSig2 keys. Duplicate keys are ignored.
    ///
    /// # Panics
    ///
    /// Panics if `operators` is empty. At least one operator is required.
    pub fn from_operator_list(operators: &[EvenPublicKey]) -> Self {
        if operators.is_empty() {
            panic!(
                "Cannot create operator table with empty entries - at least one operator is required"
            );
        }

        // Placeholder so the table is fully initialized before we compute the real aggregated key.
        let placeholder_agg_key = BitcoinXOnlyPublicKey::new([1u8; 32].into()).unwrap();

        let mut table = Self {
            next_idx: 0,
            operators: SortedVec::new_empty(),
            agg_key: placeholder_agg_key,
            historical_nn_scripts: NnScriptHistory::new_empty(),
        };

        // Reuse membership change flow to handle deduplication and seed script history.
        table.apply_membership_changes(operators, &[]);

        table
    }

    /// Returns the number of registered operators.
    pub fn len(&self) -> u32 {
        self.operators.len() as u32
    }

    /// Returns whether the operator table is empty.
    pub fn is_empty(&self) -> bool {
        self.operators.is_empty()
    }

    /// Returns a slice of all registered operator entries.
    pub fn operators(&self) -> &[OperatorEntry] {
        self.operators.as_slice()
    }

    /// Returns the aggregated public key of the current active operators.
    ///
    /// This key is computed by aggregating the MuSig2 public keys of all active operators.
    pub fn agg_key(&self) -> &BitcoinXOnlyPublicKey {
        &self.agg_key
    }

    /// Returns an iterator over all stored N/N multisig configurations in chronological order.
    ///
    /// Each [`HistoricalNnScript`] pairs a past N/N multisig script with the operator set that was
    /// active when it was current (the last entry always corresponds to the current operator set).
    /// These are used to validate slash transactions that reference stake connectors from those
    /// historical operator sets.
    pub fn historical_nn_scripts(&self) -> impl Iterator<Item = &HistoricalNnScript> {
        self.historical_nn_scripts.iter()
    }

    /// Returns the full N/N multisig configuration history.
    pub fn nn_history(&self) -> &NnScriptHistory {
        &self.historical_nn_scripts
    }

    /// Returns the configuration at `idx`, or `None` if it is out of range.
    pub fn nn_script(&self, idx: NnScriptIdx) -> Option<&HistoricalNnScript> {
        self.historical_nn_scripts.get(idx)
    }

    /// Returns the index of the current N/N multisig configuration.
    ///
    /// New deposits record this index to bind their notary set to the active configuration.
    pub fn current_nn_script_index(&self) -> NnScriptIdx {
        self.historical_nn_scripts.current_index()
    }

    /// Returns the current N/N multisig configuration for the active operator set.
    ///
    /// The latest configuration is the last entry in the history and is reused for validating new
    /// slash transactions and stake connectors without recomputing.
    pub fn current_nn_script(&self) -> &HistoricalNnScript {
        self.historical_nn_scripts.current()
    }

    /// Retrieves an operator entry by its unique index.
    ///
    /// Uses binary search for O(log n) lookup performance.
    ///
    /// # Parameters
    ///
    /// - `idx` - The unique operator index to search for
    ///
    /// # Returns
    ///
    /// - `Some(&OperatorEntry)` if the operator exists
    /// - `None` if no operator with the given index is found
    pub fn get_operator(&self, idx: OperatorIdx) -> Option<&OperatorEntry> {
        self.operators
            .as_slice()
            .binary_search_by_key(&idx, |e| e.idx)
            .ok()
            .map(|i| &self.operators.as_slice()[i])
    }

    /// Returns whether this operator is currently active in the N/N multisig set.
    ///
    /// Active operators are eligible for new task assignments, while inactive operators
    /// are preserved in the table but not assigned new tasks.
    ///
    /// # Returns
    ///
    /// `true` if the operator is active, `false` otherwise (even if the index is
    /// out-of-bounds).
    pub fn is_in_current_multisig(&self, idx: OperatorIdx) -> bool {
        self.current_multisig().is_active(idx)
    }

    /// Returns a reference to the bitmap of currently active operators.
    ///
    /// The bitmap tracks which operators are currently active in the N/N multisig configuration.
    /// It is the membership recorded in the latest `historical_nn_scripts` entry and is used for
    /// assignment creation and deposit processing.
    pub fn current_multisig(&self) -> &OperatorBitmap {
        self.current_nn_script().operators()
    }

    /// Atomically applies membership changes by adding new operators and removing existing ones,
    /// then recalculates the aggregated key.
    ///
    /// After recalculating, the new N/N script is appended to `historical_nn_scripts` so the latest
    /// script remains accessible while older entries continue to support validation for previous
    /// operator configurations.
    ///
    /// # Processing Order
    ///
    /// Additions are processed before removals. If an operator index appears in both parameters,
    /// the removal will override the addition's `is_active` value.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The changes would result in no active operators
    /// - Sequential operator insertion fails (bitmap index management error)
    /// - `next_idx` reaches `u32::MAX` when inserting new operators (since operator indices are
    ///   never reused, this limits the total number of unique operators that can ever be registered
    ///   to `u32::MAX - 1` over the bridge's lifetime; `u32::MAX` is reserved as a sentinel)
    pub fn apply_membership_changes(
        &mut self,
        add_members: &[EvenPublicKey],
        remove_members: &[OperatorIdx],
    ) {
        // Start from the current active set and mutate a copy. The set is empty only while
        // bootstrapping, before the first script is pushed.
        let initial_active = self
            .historical_nn_scripts
            .iter()
            .last()
            .map(|h| h.operators().clone())
            .unwrap_or_else(OperatorBitmap::new_empty);

        let mut active = initial_active.clone();
        self.add_operators(&mut active, add_members);
        self.remove_operators(&mut active, remove_members);

        // Record a new configuration only if the resolved set actually changed.
        if active != initial_active {
            self.record_nn_script(active);
        }
    }

    /// Recomputes the aggregated key for `active` and records the resulting N/N configuration.
    ///
    /// # Panics
    ///
    /// Panics if `active` has no active operators.
    fn record_nn_script(&mut self, active: OperatorBitmap) {
        self.agg_key = self.calculate_aggregated_key(&active);
        // The recomputed aggregated key changes the N/N deposit lock script, so surface it.
        info!(
            active_operators = active.active_indices().count(),
            agg_key = ?self.agg_key,
            "Recomputed N/N aggregated key after membership change"
        );
        self.historical_nn_scripts.push(HistoricalNnScript::new(
            build_nn_script(&self.agg_key),
            active,
        ));
    }

    /// Adds new operators to the table and marks them as active.
    ///
    /// # Duplicate Keys
    ///
    /// Duplicate public keys are **NOT** allowed. If an operator already exists in the table,
    /// the duplicate addition is ignored, and the existing operator remains unaffected.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - Sequential operator insertion fails (bitmap index management error)
    /// - `next_idx` reaches `u32::MAX` (reserved as the "no selected operator" sentinel)
    fn add_operators(&mut self, active: &mut OperatorBitmap, operators: &[EvenPublicKey]) {
        for musig2_pk in operators {
            // Check if it already exists in the table (which handles both existing operators
            // and internal duplicates in the input list, as the first occurrence is added)
            if self.operators.iter().any(|op| op.musig2_pk() == musig2_pk) {
                warn!(?musig2_pk, "Skipping duplicate operator");
                continue;
            }

            if self.next_idx == u32::MAX {
                panic!("Operator index space exhausted: u32::MAX is reserved as a sentinel");
            }

            let idx = self.next_idx;
            let entry = OperatorEntry {
                idx,
                musig2_pk: *musig2_pk,
            };

            // SortedVec handles insertion and maintains sorted order
            self.operators.insert(entry);

            // Set new operator as active in bitmap
            active
                .try_set(idx, true)
                .expect("Sequential operator insertion should always succeed");

            debug!(operator_idx = idx, "Added operator");
            self.next_idx += 1;
        }
    }

    /// Deactivates existing operators by their indices.
    fn remove_operators(&mut self, active: &mut OperatorBitmap, indices: &[OperatorIdx]) {
        for &idx in indices {
            // Only update if the operator exists
            if self
                .operators
                .as_slice()
                .binary_search_by_key(&idx, |e| e.idx)
                .is_ok()
            {
                // For existing operators, we can set their status directly
                if (idx as usize) < active.len() {
                    active
                        .try_set(idx, false)
                        .expect("Setting existing operator status should succeed");
                    debug!(operator_idx = idx, "Deactivated operator");
                }
            } else {
                warn!(operator_idx = idx, "Skipping removal of unknown operator");
            }
        }
    }

    /// Computes the aggregated MuSig2 key for the given active operator set.
    ///
    /// This is a pure calculation: it does not mutate the table. The sole writer of `self.agg_key`
    /// is `Self::record_nn_script`, which pairs the key with the configuration it records.
    ///
    /// # Panics
    ///
    /// Panics if there are no active operators.
    fn calculate_aggregated_key(&self, active: &OperatorBitmap) -> BitcoinXOnlyPublicKey {
        let active_keys: Vec<Buf32> = active
            .active_indices()
            .filter_map(|op| {
                self.get_operator(op)
                    .map(|entry| Buf32::from(entry.musig2_pk().x_only_public_key().0.serialize()))
            })
            .collect();

        if active_keys.is_empty() {
            panic!("Cannot have empty multisig - at least one operator must be active");
        }

        aggregate_schnorr_keys(active_keys.iter())
            .expect("Failed to generate aggregated key")
            .into()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{SECP256K1, SecretKey};

    use super::*;

    /// Creates test operator MuSig2 public keys with randomly generated valid secp256k1 keys
    fn create_test_operator_pubkeys(count: usize) -> Vec<EvenPublicKey> {
        use bitcoin::secp256k1::rand;
        let mut keys = Vec::with_capacity(count);

        for _ in 0..count {
            // Generate random MuSig2 key
            let sk = SecretKey::new(&mut rand::thread_rng());
            let pk = sk.public_key(SECP256K1);
            keys.push(EvenPublicKey::from(pk));
        }

        keys
    }

    #[test]
    #[should_panic(
        expected = "Cannot create operator table with empty entries - at least one operator is required"
    )]
    fn test_operator_table_empty_entries_panics() {
        OperatorTable::from_operator_list(&[]);
    }

    #[test]
    fn test_operator_table_from_operator_list() {
        let operators = create_test_operator_pubkeys(3);
        let table = OperatorTable::from_operator_list(&operators);

        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
        assert_eq!(table.next_idx, 3);

        // Verify all operators are present in the table
        // Note: Indices may not match input order due to HashSet deduplication
        for op_pk in &operators {
            let found = table
                .operators()
                .iter()
                .any(|entry| entry.musig2_pk() == op_pk);
            assert!(found, "Operator {:?} not found in table", op_pk);
        }

        // precise index check is no longer valid as order is not guaranteed
        for entry in table.operators() {
            assert!(table.is_in_current_multisig(entry.idx()));
        }
    }

    #[test]
    fn test_operator_table_insert() {
        let initial_operators = create_test_operator_pubkeys(1);
        let mut table = OperatorTable::from_operator_list(&initial_operators);

        let new_operators = create_test_operator_pubkeys(2);
        table.apply_membership_changes(&new_operators, &[]);

        assert_eq!(table.len(), 3);
        assert_eq!(table.next_idx, 3);

        // Verify inserted operators are correctly stored and active
        for (i, op_pk) in new_operators.iter().enumerate() {
            let idx = (i + 1) as u32;
            let entry = table.get_operator(idx).unwrap();
            assert_eq!(entry.idx(), idx);
            assert_eq!(entry.musig2_pk(), op_pk);
            assert!(table.is_in_current_multisig(idx));
        }
    }

    #[test]
    fn test_operator_table_insert_duplicate() {
        let initial_operators = create_test_operator_pubkeys(1);
        let mut table = OperatorTable::from_operator_list(&initial_operators);

        // Try to add the same operator again - should be silently ignored
        table.apply_membership_changes(&initial_operators, &[]);

        // Check that state hasn't changed (still 1 operator)
        assert_eq!(table.len(), 1);
        assert_eq!(table.next_idx, 1);
    }

    #[test]
    fn test_operator_table_create_with_duplicate_deduplicates() {
        let mut operators = create_test_operator_pubkeys(2);
        operators[1] = operators[0]; // Duplicate key

        let table = OperatorTable::from_operator_list(&operators);

        // Should have deduplicated to just 1 operator
        assert_eq!(table.len(), 1);
        assert_eq!(table.next_idx, 1);
        assert_eq!(*table.get_operator(0).unwrap().musig2_pk(), operators[0]);
    }

    #[test]
    fn test_operator_table_add_internal_duplicates() {
        let initial_operators = create_test_operator_pubkeys(1);
        let mut table = OperatorTable::from_operator_list(&initial_operators);

        let new_operators = create_test_operator_pubkeys(1);
        // Try to add the same new operator twice in the same batch
        let duplicates = vec![new_operators[0], new_operators[0]];

        table.apply_membership_changes(&duplicates, &[]);

        // Should have only added one new operator
        assert_eq!(table.len(), 2);
        assert_eq!(table.next_idx, 2);
    }

    #[test]
    fn test_operator_table_update_active_status() {
        let operators = create_test_operator_pubkeys(3);
        let mut table = OperatorTable::from_operator_list(&operators);

        // Initially all operators should be active
        assert!(table.is_in_current_multisig(0));
        assert!(table.is_in_current_multisig(1));
        assert!(table.is_in_current_multisig(2));

        // Update multiple operators at once
        let removals = vec![0, 2];
        table.apply_membership_changes(&[], &removals);
        assert!(!table.is_in_current_multisig(0));
        assert!(table.is_in_current_multisig(1)); // unchanged
        assert!(!table.is_in_current_multisig(2));

        // Test re-adding operator 0
        let additions = vec![0];
        table.apply_membership_changes(&[], &additions);

        // Operator 0 should remain inactive (it was already added)
        assert!(!table.is_in_current_multisig(0));
    }

    #[test]
    fn test_active_operators_indices() {
        let operators = create_test_operator_pubkeys(3);
        let mut table = OperatorTable::from_operator_list(&operators);

        // Initially, all operators should be active
        let active_indices: Vec<_> = table.current_multisig().active_indices().collect();
        assert_eq!(active_indices, vec![0, 1, 2]);

        // Mark operator 1 as inactive
        table.apply_membership_changes(&[], &[1]);

        // Now only operators 0 and 2 should be active
        let active_indices: Vec<_> = table.current_multisig().active_indices().collect();
        assert_eq!(active_indices, vec![0, 2]);
    }

    #[test]
    fn test_historical_nn_scripts_tracking() {
        let operators = create_test_operator_pubkeys(3);
        let mut table = OperatorTable::from_operator_list(&operators);

        let historical_scripts: Vec<_> = table.historical_nn_scripts().collect();
        assert_eq!(historical_scripts.len(), 1);
        let initial_script = table.current_nn_script().script().clone();
        assert_eq!(historical_scripts[0].script(), &initial_script);

        table.apply_membership_changes(&[], &[0]);

        let second_script = table.current_nn_script().script().clone();
        assert_ne!(second_script, initial_script);

        let historical_scripts: Vec<_> = table.historical_nn_scripts().collect();
        assert_eq!(historical_scripts.len(), 2);
        assert_eq!(historical_scripts[0].script(), &initial_script);
        assert_eq!(historical_scripts[1].script(), &second_script);

        table.apply_membership_changes(&[], &[1]);

        let third_script = table.current_nn_script().script().clone();
        assert_ne!(third_script, second_script);

        let historical_scripts: Vec<_> = table.historical_nn_scripts().collect();
        assert_eq!(historical_scripts.len(), 3);
        assert_eq!(historical_scripts[0].script(), &initial_script);
        assert_eq!(historical_scripts[1].script(), &second_script);
        assert_eq!(historical_scripts[2].script(), &third_script);

        assert_ne!(initial_script, second_script);
        assert_ne!(second_script, third_script);
        assert_ne!(initial_script, third_script);
    }

    #[test]
    fn test_no_op_membership_change_does_not_grow_history() {
        let operators = create_test_operator_pubkeys(3);
        let mut table = OperatorTable::from_operator_list(&operators);
        assert_eq!(table.historical_nn_scripts().count(), 1);

        // Removing an operator that isn't registered resolves to the same active set.
        table.apply_membership_changes(&[], &[99]);
        assert_eq!(table.historical_nn_scripts().count(), 1);

        // Re-adding an operator that is already active is deduplicated away.
        table.apply_membership_changes(&[operators[0]], &[]);
        assert_eq!(table.historical_nn_scripts().count(), 1);

        // Removing an operator that is already inactive is also a no-op.
        table.apply_membership_changes(&[], &[0]);
        assert_eq!(table.historical_nn_scripts().count(), 2);
        table.apply_membership_changes(&[], &[0]);
        assert_eq!(table.historical_nn_scripts().count(), 2);
    }

    #[test]
    fn test_historical_scripts_on_additions() {
        let operators = create_test_operator_pubkeys(3);
        let mut table = OperatorTable::from_operator_list(&operators);

        let historical_scripts: Vec<_> = table.historical_nn_scripts().collect();
        assert_eq!(historical_scripts.len(), 1);
        let initial_script = table.current_nn_script().script().clone();

        let new_operators = create_test_operator_pubkeys(2);
        table.apply_membership_changes(&new_operators, &[]);

        let new_script = table.current_nn_script().script().clone();
        assert_ne!(new_script, initial_script);

        let historical_scripts: Vec<_> = table.historical_nn_scripts().collect();
        assert_eq!(historical_scripts.len(), 2);
        assert_eq!(historical_scripts[0].script(), &initial_script);
        assert_eq!(historical_scripts[1].script(), &new_script);
    }
}
