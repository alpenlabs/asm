//! Bitcoin Deposit Management
//!
//! This module contains types and tables for managing Bitcoin deposits in the bridge.
//! Deposits represent Bitcoin UTXOs locked to N/N multisig addresses where N are the
//! notary operators. We preserve the historical operator set that controlled each deposit
//! since the operator set may change over time.

use std::cmp;

use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_asm_common::sorted_vec::SortedVec;
use strata_btc_types::BitcoinAmount;

use crate::{errors::DepositValidationError, state::operator::NnScriptIdx};

/// Bitcoin deposit entry containing UTXO reference and historical multisig operators.
///
/// Each deposit represents a Bitcoin UTXO that has been locked to an N/N multisig
/// address where N are the notary operators. The deposit tracks:
///
/// - **`deposit_idx`** - Unique identifier assigned by the bridge for this deposit
/// - **`notary_set`** - Index of the N/N multisig configuration that controls this deposit
/// - **`amt`** - Amount of Bitcoin locked in this deposit
///
/// # Index Assignment
///
/// The `deposit_idx` is assigned by the bridge and provided in the deposit transaction.
/// The bridge determines the indexing strategy, which may be based on either
/// `DepositRequestTransaction` or `DepositTransaction` ordering, depending on the
/// bridge's implementation needs.
///
/// This bridge-controlled ordering is essential for the stake chain to maintain
/// consistent deposit sequencing across all participants.
///
/// # Multisig Design
///
/// The `notary_set` field references the historical N/N multisig configuration that controlled
/// this deposit when it was locked, since the active operator set may change over time. Any one
/// honest operator from that set can process user withdrawals. Rather than copying the operator
/// bitmap into every deposit, we store the index of the configuration in the operator table's
/// `NnScriptHistory`, which holds the bitmap once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct DepositEntry {
    /// Unique deposit identifier assigned by the bridge and provided in the deposit transaction.
    deposit_idx: u32,

    /// Index into the operator table's N/N script history identifying the multisig configuration
    /// that controlled this deposit when it was locked.
    notary_set: NnScriptIdx,

    /// Amount of Bitcoin locked in this deposit (in satoshis).
    amt: BitcoinAmount,
}

impl PartialOrd for DepositEntry {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DepositEntry {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.idx().cmp(&other.idx())
    }
}

impl DepositEntry {
    /// Creates a new deposit entry with the specified parameters.
    ///
    /// # Parameters
    ///
    /// - `idx` - Unique deposit identifier
    /// - `notary_set` - Index of the N/N multisig configuration controlling this deposit
    /// - `amt` - Amount of Bitcoin locked in the deposit
    pub fn new(idx: u32, notary_set: NnScriptIdx, amt: BitcoinAmount) -> Self {
        Self {
            deposit_idx: idx,
            notary_set,
            amt,
        }
    }

    /// Returns the unique deposit identifier.
    pub fn idx(&self) -> u32 {
        self.deposit_idx
    }

    /// Returns the index of the N/N multisig configuration that controls this deposit.
    ///
    /// Resolve it against the operator table's
    /// `NnScriptHistory` to recover the notary operator bitmap.
    pub fn notary_set(&self) -> NnScriptIdx {
        self.notary_set
    }

    /// Returns the amount of Bitcoin locked in this deposit.
    pub fn amt(&self) -> BitcoinAmount {
        self.amt
    }
}

impl<'a> Arbitrary<'a> for DepositEntry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let deposit_idx: u32 = u.arbitrary()?;
        let notary_set: NnScriptIdx = u.arbitrary()?;
        let amount: BitcoinAmount = u.arbitrary()?;

        Ok(Self::new(deposit_idx, notary_set, amount))
    }
}

/// Table for managing Bitcoin deposits with efficient lookup operations.
///
/// This table maintains all deposits tracked by the bridge, providing efficient
/// insertion and lookup operations. The table maintains sorted order for binary search efficiency.
///
/// # Ordering Invariant
///
/// The deposits vector **MUST** remain sorted by deposit index at all times.
/// This invariant enables O(log n) lookup operations via binary search.
///
/// # Index Management
///
/// - Deposit indices are provided by the caller (from DepositInfo)
/// - Out-of-order insertions are supported and maintain sorted order
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositsTable {
    /// Vector of deposit entries, sorted by deposit index.
    ///
    /// **Invariant**: MUST be sorted by `DepositEntry::deposit_idx` field.
    deposits: SortedVec<DepositEntry>,
}

#[derive(Debug, Encode, Decode)]
struct DepositsTableSsz {
    deposits: Vec<DepositEntry>,
}

impl From<&DepositsTable> for DepositsTableSsz {
    fn from(value: &DepositsTable) -> Self {
        Self {
            deposits: value.deposits.to_vec(),
        }
    }
}

impl SszEncode for DepositsTable {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        DepositsTableSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        DepositsTableSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for DepositsTable {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let payload = DepositsTableSsz::from_ssz_bytes(bytes)?;
        let deposits = SortedVec::try_from(payload.deposits).map_err(|_| {
            DecodeError::BytesInvalid("deposits table entries must stay sorted".into())
        })?;
        Ok(Self { deposits })
    }
}

impl DepositsTable {
    /// Creates a new empty deposits table.
    ///
    /// Initializes the table with no deposits, ready for deposit registrations.
    ///
    /// # Returns
    ///
    /// A new empty [`DepositsTable`].
    pub fn new_empty() -> Self {
        Self {
            deposits: SortedVec::new_empty(),
        }
    }

    /// Returns the number of deposits being tracked.
    ///
    /// # Returns
    ///
    /// The total count of deposits in the table as [`u32`].
    pub fn len(&self) -> u32 {
        self.deposits.len() as u32
    }

    /// Returns whether the deposits table is empty.
    ///
    /// In practice, this will typically return `false` once deposits start
    /// being processed by the bridge.
    ///
    /// # Returns
    ///
    /// `true` if no deposits are tracked, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Retrieves a deposit entry by its index using binary search.
    ///
    /// Performs an efficient O(log n) lookup to find the deposit with the specified index.
    /// Takes advantage of the sorted order invariant maintained by the deposits vector.
    ///
    /// # Parameters
    ///
    /// - `deposit_idx` - The unique deposit index to search for
    ///
    /// # Returns
    ///
    /// - `Some(&DepositEntry)` if a deposit with the given index exists
    /// - `None` if no deposit with the given index is found
    pub fn get_deposit(&self, deposit_idx: u32) -> Option<&DepositEntry> {
        self.deposits
            .as_slice()
            .binary_search_by_key(&deposit_idx, |entry| entry.deposit_idx)
            .ok()
            .map(|pos| &self.deposits.as_slice()[pos])
    }

    /// Returns an iterator over all deposit entries.
    ///
    /// The entries are returned in sorted order by deposit index.
    ///
    /// # Returns
    ///
    /// Iterator yielding references to all [`DepositEntry`] instances.
    pub fn deposits(&self) -> impl Iterator<Item = &DepositEntry> {
        self.deposits.iter()
    }

    /// Inserts a deposit entry into the table at the correct position.
    ///
    /// Takes an existing [`DepositEntry`] and inserts it into the deposits table,
    /// maintaining sorted order by deposit index. Uses binary search to find the
    /// optimal insertion point.
    ///
    /// # Parameters
    ///
    /// - `entry` - The deposit entry to insert
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the deposit was successfully inserted
    /// - `Err(DepositValidationError::DepositIdxAlreadyExists)` if a deposit with this index
    ///   already exists
    pub fn insert_deposit(&mut self, entry: DepositEntry) -> Result<(), DepositValidationError> {
        let idx = entry.deposit_idx;
        match self.get_deposit(idx) {
            Some(_) => Err(DepositValidationError::DepositIdxAlreadyExists(idx)),
            None => {
                // SortedVec handles insertion and maintains sorted order
                self.deposits.insert(entry);
                Ok(())
            }
        }
    }

    /// Removes and returns the oldest deposit from the table.
    ///
    /// Since the table is sorted by deposit index, the oldest deposit (with the
    /// smallest deposit_idx) is always at position 0. This method removes and
    /// returns that deposit.
    ///
    /// # Returns
    ///
    /// - `Some(DepositEntry)` if there are deposits in the table
    /// - `None` if the table is empty
    pub fn remove_oldest_deposit(&mut self) -> Option<DepositEntry> {
        if self.deposits.is_empty() {
            None
        } else {
            // Get the first (oldest) deposit and remove it
            let oldest = self.deposits.as_slice()[0].clone();
            self.deposits.remove(&oldest);
            Some(oldest)
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::{collection, prelude::*, prop_assert, prop_assert_eq, proptest};
    use strata_btc_types::BitcoinAmount;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    #[test]
    fn test_deposits_table_insert_single() {
        let mut table = DepositsTable::new_empty();
        let entry: DepositEntry = ArbitraryGenerator::new().generate();

        let result = table.insert_deposit(entry.clone());
        assert!(result.is_ok());

        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        let retrieved = table
            .get_deposit(entry.idx())
            .expect("must find inserted deposit");
        assert_eq!(&entry, retrieved);
    }

    #[test]
    fn test_deposits_table_insert_duplicate_idx() {
        let mut table = DepositsTable::new_empty();

        let entry1: DepositEntry = ArbitraryGenerator::new().generate();
        let deposit_idx = entry1.deposit_idx;
        assert!(table.insert_deposit(entry1).is_ok());

        let mut entry2: DepositEntry = ArbitraryGenerator::new().generate();
        entry2.deposit_idx = deposit_idx; // Force duplicate index

        let result = table.insert_deposit(entry2.clone());
        assert!(matches!(
            result,
            Err(DepositValidationError::DepositIdxAlreadyExists(idx)) if idx == deposit_idx
        ));
    }

    /// Strategy for generating a `Vec` of [`DepositEntry`] with unique indices.
    fn unique_deposit_entries_strategy(count: usize) -> impl Strategy<Value = Vec<DepositEntry>> {
        collection::hash_set(any::<u32>(), count).prop_flat_map(move |indices| {
            let entry_strategies: Vec<_> = indices
                .into_iter()
                .map(|idx| {
                    (any::<u32>(), 1u64..=2_100_000_000_000).prop_map(move |(notary_set, sats)| {
                        DepositEntry::new(idx, notary_set, BitcoinAmount::from_sat(sats))
                    })
                })
                .collect();
            entry_strategies
        })
    }

    proptest! {
        #[test]
        fn test_deposits_table_inserts_and_removals(
            entries in unique_deposit_entries_strategy(10),
        ) {
            let mut table = DepositsTable::new_empty();
            let len = entries.len() as u32;

            prop_assert_eq!(table.len(), 0);
            prop_assert!(table.is_empty());

            for entry in entries {
                prop_assert!(table.insert_deposit(entry).is_ok());
            }
            prop_assert_eq!(table.len(), len);

            // Verify they are stored in sorted order.
            let deposit_indices: Vec<_> = table.deposits().map(|e| e.deposit_idx).collect();
            prop_assert!(deposit_indices.is_sorted());

            let mut removed_indices = Vec::new();
            for i in 0..len {
                let removed = table.remove_oldest_deposit();
                prop_assert!(removed.is_some());
                let idx = removed.unwrap().idx();
                removed_indices.push(idx);
                prop_assert!(table.len() == (len - i - 1));
            }
            prop_assert!(table.remove_oldest_deposit().is_none());

            prop_assert!(removed_indices.is_sorted());
        }
    }
}
