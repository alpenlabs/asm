//! Operator Assignment Management
//!
//! This module contains types and tables for managing operator assignments to deposits.
//! Assignments link specific deposit UTXOs to operators who are responsible for processing
//! the corresponding withdrawal requests within specified deadlines.

use std::cmp::Ordering;

use arbitrary::Arbitrary;
use rand_chacha::{
    ChaChaRng,
    rand_core::{RngCore, SeedableRng},
};
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_asm_common::sorted_vec::SortedVec;
use strata_asm_proto_bridge_v1_types::{
    OperatorBitmap, OperatorIdx, WithdrawalIntent, WithdrawalOutput, filter_eligible_operators,
};
use strata_btc_types::BitcoinAmount;
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId, L1Height};

use crate::{
    errors::WithdrawalAssignmentError,
    state::{
        deposit::DepositEntry,
        operator::{NnScriptHistory, NnScriptIdx},
    },
};

/// Links a deposit UTXO to the operator responsible for fulfilling its withdrawal.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Serialize, Deserialize, Encode, Decode)]
pub struct AssignmentEntry {
    /// Deposit entry that has been assigned
    deposit_entry: DepositEntry,

    /// The Bitcoin output this assignment must pay out: destination and amount.
    withdrawal_output: WithdrawalOutput,

    /// Amount the operator can take as fees for processing the withdrawal.
    ///
    /// Deducted from the withdrawal amount: the user receives the net amount
    /// (see [`net_amount`](Self::net_amount)) and the operator keeps this fee.
    operator_fee: BitcoinAmount,

    /// Index of the operator currently assigned to execute this withdrawal.
    ///
    /// If they successfully front the withdrawal based on `withdrawal_output`
    /// within the `fulfillment_deadline`, they are able to unlock their claim.
    current_assignee: OperatorIdx,

    /// Bitmap of operators who were previously assigned to this withdrawal.
    ///
    /// When a withdrawal is reassigned, the current assignee is marked in this
    /// bitmap before a new operator is selected. This prevents reassigning to
    /// operators who have already failed to execute the withdrawal.
    previous_assignees: OperatorBitmap,

    /// Bitcoin block height deadline for withdrawal execution.
    ///
    /// The withdrawal fulfillment transaction must be executed before this block height for the
    /// operator to be eligible for [`ClaimUnlock`](super::withdrawal::OperatorClaimUnlock).
    fulfillment_deadline: L1Height,
}

impl PartialOrd for AssignmentEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssignmentEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.deposit_entry.cmp(&other.deposit_entry)
    }
}

impl AssignmentEntry {
    /// Creates a new assignment, selecting the assignee from the deposit's eligible operators.
    ///
    /// Honors the withdrawal intent's preferred operator when it is still eligible; otherwise
    /// picks one deterministically at random.
    ///
    /// Returns [`WithdrawalAssignmentError::NoEligibleOperators`] if no operator from the
    /// deposit's notary set is currently active.
    ///
    /// `notary_operators` is the bitmap of the deposit's notary set, resolved by the caller from
    /// the deposit's [`notary_set`](DepositEntry::notary_set) index.
    pub fn create(
        deposit_entry: DepositEntry,
        withdrawal_intent: WithdrawalIntent,
        operator_fee: BitcoinAmount,
        fulfillment_deadline: L1Height,
        notary_operators: &OperatorBitmap,
        current_active_operators: &OperatorBitmap,
        seed: L1BlockId,
    ) -> Result<Self, WithdrawalAssignmentError> {
        // No operators have been tried yet.
        let previous_assignees = OperatorBitmap::new_with_size(notary_operators.len(), false);

        let eligible = filter_eligible_operators(
            notary_operators,
            &previous_assignees,
            current_active_operators,
        )?;

        // Honor the user's preferred operator when eligible; otherwise pick one at random.
        let current_assignee = match withdrawal_intent
            .selected_operator()
            .as_specific()
            .filter(|&idx| eligible.is_active(idx))
        {
            Some(idx) => idx,
            None => select_random_operator(&eligible, seed, deposit_entry.idx())?,
        };

        Ok(Self {
            deposit_entry,
            withdrawal_output: withdrawal_intent.to_output(),
            operator_fee,
            current_assignee,
            previous_assignees,
            fulfillment_deadline,
        })
    }

    /// Returns the deposit index associated with this assignment.
    pub fn deposit_idx(&self) -> u32 {
        self.deposit_entry.idx()
    }

    /// Returns the N/N script history index identifying this deposit's notary set.
    pub fn notary_set(&self) -> NnScriptIdx {
        self.deposit_entry.notary_set()
    }

    /// Returns a reference to the withdrawal output.
    pub fn withdrawal_output(&self) -> &WithdrawalOutput {
        &self.withdrawal_output
    }

    /// Returns the operator fee deducted from this withdrawal.
    pub fn operator_fee(&self) -> BitcoinAmount {
        self.operator_fee
    }

    /// Returns the amount the user receives: the withdrawal amount minus the operator fee.
    pub fn net_amount(&self) -> BitcoinAmount {
        self.withdrawal_output
            .amt()
            .saturating_sub(self.operator_fee)
    }

    /// Returns the index of the currently assigned operator.
    pub fn current_assignee(&self) -> OperatorIdx {
        self.current_assignee
    }

    /// Returns the fulfillment deadline for this assignment.
    pub fn fulfillment_deadline(&self) -> L1Height {
        self.fulfillment_deadline
    }

    /// Reassigns the withdrawal to a different operator and updates the fulfillment deadline.
    ///
    /// Marks the current assignee as tried and selects a new operator from those not yet tried.
    /// Once every operator has been tried, the history is cleared and selection draws from the
    /// full active set again.
    pub fn reassign(
        &mut self,
        new_deadline: L1Height,
        seed: L1BlockId,
        notary_operators: &OperatorBitmap,
        current_active_operators: &OperatorBitmap,
    ) -> Result<(), WithdrawalAssignmentError> {
        // Mark the current assignee as tried so we don't immediately reselect it.
        self.previous_assignees
            .try_set(self.current_assignee, true)
            .map_err(WithdrawalAssignmentError::BitmapError)?;

        let deposit_idx = self.deposit_entry.idx();

        // Prefer an operator that hasn't been tried yet; once every operator has been tried,
        // reset the history and reselect from the full active set.
        let eligible = filter_eligible_operators(
            notary_operators,
            &self.previous_assignees,
            current_active_operators,
        )?;
        let new_assignee = match select_random_operator(&eligible, seed, deposit_idx) {
            Ok(operator) => operator,
            Err(WithdrawalAssignmentError::NoEligibleOperators { .. }) => {
                self.previous_assignees =
                    OperatorBitmap::new_with_size(notary_operators.len(), false);
                let eligible = filter_eligible_operators(
                    notary_operators,
                    &self.previous_assignees,
                    current_active_operators,
                )?;
                select_random_operator(&eligible, seed, deposit_idx)?
            }
            Err(err) => return Err(err),
        };

        self.current_assignee = new_assignee;
        self.fulfillment_deadline = new_deadline;
        Ok(())
    }
}

/// Deterministically selects one operator from `eligible`, keyed by `(seed, deposit_idx)`.
///
/// The L1 block id seeds `ChaChaRng` and the deposit index selects the ChaCha20 stream, so
/// selections anchored to the same block draw from independent streams rather than collapsing
/// onto a single operator.
///
/// Returns [`WithdrawalAssignmentError::NoEligibleOperators`] when `eligible` is empty:
/// `checked_rem` yields `None` for a zero-length set, and `nth` otherwise always succeeds since
/// the index is `< active_count`.
fn select_random_operator(
    eligible: &OperatorBitmap,
    seed: L1BlockId,
    deposit_idx: u32,
) -> Result<OperatorIdx, WithdrawalAssignmentError> {
    let seed_bytes: [u8; 32] = Buf32::from(seed).into();
    let mut rng = ChaChaRng::from_seed(seed_bytes);
    rng.set_stream(deposit_idx as u64);

    (rng.next_u32() as usize)
        .checked_rem(eligible.active_count())
        .and_then(|index| eligible.active_indices().nth(index))
        .ok_or(WithdrawalAssignmentError::NoEligibleOperators { deposit_idx })
}

/// A table of operator assignments, kept sorted by deposit index.
///
/// # Ordering Invariant
///
/// The entries **MUST** stay sorted by deposit index; this is what makes
/// [`get_assignment`](Self::get_assignment) an O(log n) binary search.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentTable {
    /// Assignment entries, sorted by deposit index.
    assignments: SortedVec<AssignmentEntry>,

    /// The duration (in blocks) for which the operator is assigned to fulfill the withdrawal.
    /// If the operator fails to complete the withdrawal within this period, the assignment
    /// will be reassigned to another operator.
    assignment_duration: u16,
}

#[derive(Debug, Encode, Decode)]
struct AssignmentTableSsz {
    assignments: Vec<AssignmentEntry>,
    assignment_duration: u16,
}

impl From<&AssignmentTable> for AssignmentTableSsz {
    fn from(value: &AssignmentTable) -> Self {
        Self {
            assignments: value.assignments.to_vec(),
            assignment_duration: value.assignment_duration,
        }
    }
}

impl SszEncode for AssignmentTable {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        AssignmentTableSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        AssignmentTableSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for AssignmentTable {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let payload = AssignmentTableSsz::from_ssz_bytes(bytes)?;
        let assignments = SortedVec::try_from(payload.assignments).map_err(|_| {
            DecodeError::BytesInvalid("assignment table entries must stay sorted".into())
        })?;
        Ok(Self {
            assignments,
            assignment_duration: payload.assignment_duration,
        })
    }
}

impl AssignmentTable {
    /// Creates an empty assignment table.
    pub fn new(assignment_duration: u16) -> Self {
        Self {
            assignments: SortedVec::new_empty(),
            assignment_duration,
        }
    }

    /// Calculates the fulfillment deadline for an assignment anchored at `current_height`,
    /// `assignment_duration` blocks later.
    fn calculate_deadline(&self, current_height: L1Height) -> L1Height {
        current_height + self.assignment_duration as u32
    }

    /// Returns the number of assignments in the table.
    pub fn len(&self) -> u32 {
        self.assignments.len() as u32
    }

    /// Returns whether the assignment table is empty.
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Returns a slice of all assignment entries.
    pub fn assignments(&self) -> &[AssignmentEntry] {
        self.assignments.as_slice()
    }

    /// Returns the assignment for `deposit_idx`, or `None` if there is none.
    pub fn get_assignment(&self, deposit_idx: u32) -> Option<&AssignmentEntry> {
        let assignments = self.assignments.as_slice();
        let idx = assignments
            .binary_search_by_key(&deposit_idx, |entry| entry.deposit_idx())
            .ok()?;
        Some(&assignments[idx])
    }

    /// Inserts an assignment, preserving the sort order.
    ///
    /// # Panics
    ///
    /// Panics if an assignment with the same deposit index already exists.
    pub fn insert(&mut self, entry: AssignmentEntry) {
        if self.get_assignment(entry.deposit_idx()).is_some() {
            panic!(
                "Assignment with deposit index {} already exists",
                entry.deposit_idx()
            );
        }
        self.assignments.insert(entry);
    }

    /// Removes and returns the assignment for `deposit_idx`, or `None` if there is none.
    pub fn remove_assignment(&mut self, deposit_idx: u32) -> Option<AssignmentEntry> {
        let assignment = self.get_assignment(deposit_idx)?.clone();
        if self.assignments.remove(&assignment) {
            Some(assignment)
        } else {
            None
        }
    }

    /// Reassigns every assignment whose deadline has passed, returning their deposit indices.
    ///
    /// Keeps withdrawals from stalling on unresponsive operators. All-or-nothing: if any expired
    /// assignment has no eligible operator, the whole call errors.
    pub fn reassign_expired_assignments(
        &mut self,
        nn_history: &NnScriptHistory,
        current_active_operators: &OperatorBitmap,
        l1_block: &L1BlockCommitment,
    ) -> Result<Vec<u32>, WithdrawalAssignmentError> {
        let mut reassigned_withdrawals = Vec::new();

        let current_height = l1_block.height();
        let seed = *l1_block.blkid();
        let new_deadline = self.calculate_deadline(current_height);

        // Using iter_mut since we're only modifying non-sorting fields
        for assignment in self
            .assignments
            .iter_mut()
            .filter(|e| e.fulfillment_deadline <= current_height)
        {
            let notary_operators = nn_history
                .get(assignment.notary_set())
                .expect("assignment references a known N/N configuration")
                .operators();
            assignment.reassign(
                new_deadline,
                seed,
                notary_operators,
                current_active_operators,
            )?;
            reassigned_withdrawals.push(assignment.deposit_idx());
        }

        Ok(reassigned_withdrawals)
    }

    /// Builds an assignment for the deposit (see [`AssignmentEntry::create`]) and inserts it,
    /// deriving the fulfillment deadline from the current L1 height and the assignment duration.
    pub fn add_new_assignment(
        &mut self,
        deposit_entry: DepositEntry,
        withdrawal_intent: WithdrawalIntent,
        operator_fee: BitcoinAmount,
        notary_operators: &OperatorBitmap,
        current_active_operators: &OperatorBitmap,
        l1_block: &L1BlockCommitment,
    ) -> Result<(), WithdrawalAssignmentError> {
        let fulfillment_deadline = self.calculate_deadline(l1_block.height());

        let entry = AssignmentEntry::create(
            deposit_entry,
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            notary_operators,
            current_active_operators,
            *l1_block.blkid(),
        )?;

        self.assignments.insert(entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_proto_bridge_v1_types::{OperatorBitmapError, OperatorSelection};
    use strata_identifiers::{L1BlockId, L1Height};
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    #[test]
    fn test_create_success() {
        let mut arb = ArbitraryGenerator::new();
        let deposit_entry: DepositEntry = arb.generate();
        let withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed: L1BlockId = arb.generate();

        let notary_operators = OperatorBitmap::new_with_size(3, true);
        let current_active_operators = notary_operators.clone();

        let result = AssignmentEntry::create(
            deposit_entry.clone(),
            withdrawal_intent.clone(),
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed,
        );

        assert!(result.is_ok());
        let assignment = result.unwrap();

        // Verify assignment properties
        assert_eq!(assignment.deposit_idx(), deposit_entry.idx());
        assert_eq!(
            assignment.withdrawal_output(),
            &withdrawal_intent.to_output()
        );
        assert_eq!(assignment.operator_fee(), operator_fee);
        assert_eq!(assignment.fulfillment_deadline(), fulfillment_deadline);
        assert!(current_active_operators.is_active(assignment.current_assignee()));
        assert_eq!(assignment.previous_assignees.active_count(), 0);
    }

    #[test]
    fn test_create_with_selected_operator() {
        let mut arb = ArbitraryGenerator::new();

        let deposit_entry: DepositEntry = arb.generate();

        let mut withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed: L1BlockId = arb.generate();
        // At least 3 active operators so we can pick a specific one.
        let notary_operators = OperatorBitmap::new_with_size(3, true);
        let current_active_operators = notary_operators.clone();

        // Prefer the second active operator.
        let selected_idx = current_active_operators
            .active_indices()
            .nth(1)
            .expect("at least 3 active operators");
        withdrawal_intent.selected_operator = OperatorSelection::specific(selected_idx);

        let assignment = AssignmentEntry::create(
            deposit_entry,
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed,
        )
        .unwrap();

        assert_eq!(assignment.current_assignee(), selected_idx);
    }

    #[test]
    fn test_create_with_ineligible_selected_operator_falls_back_to_random() {
        let mut arb = ArbitraryGenerator::new();
        let deposit_entry: DepositEntry = arb.generate();

        let mut withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed: L1BlockId = arb.generate();
        let notary_operators = OperatorBitmap::new_with_size(2, true);
        let current_active_operators = notary_operators.clone();

        // Prefer an out-of-range index that won't be eligible.
        let bogus_idx = current_active_operators.len() as u32 + 100;
        withdrawal_intent.selected_operator = OperatorSelection::specific(bogus_idx);

        let assignment = AssignmentEntry::create(
            deposit_entry,
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed,
        )
        .unwrap();

        // Should still get assigned to a valid active operator via random fallback
        assert!(current_active_operators.is_active(assignment.current_assignee()));
        assert_ne!(assignment.current_assignee(), bogus_idx);
        assert!(assignment.current_assignee() < current_active_operators.len() as u32);
    }

    #[test]
    fn test_create_no_eligible_operators() {
        let mut arb = ArbitraryGenerator::new();
        let deposit_entry: DepositEntry = arb.generate();
        let withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed: L1BlockId = arb.generate();

        // Non-empty notary set, but no active operators: the active bitmap is shorter than the
        // notary set, so eligibility filtering rejects it.
        let notary_operators = OperatorBitmap::new_with_size(3, true);
        let current_active_operators = OperatorBitmap::new_empty();

        let err = AssignmentEntry::create(
            deposit_entry.clone(),
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            WithdrawalAssignmentError::BitmapError(
                OperatorBitmapError::InsufficientActiveBitmapLength { .. }
            )
        ));
    }

    #[test]
    fn test_reassign_success() {
        let mut arb = ArbitraryGenerator::new();

        let deposit_entry: DepositEntry = arb.generate();

        let withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed1: L1BlockId = arb.generate();
        let seed2: L1BlockId = arb.generate();

        // At least 2 active operators so reassignment can pick a different one.
        let notary_operators = OperatorBitmap::new_with_size(3, true);
        let current_active_operators = notary_operators.clone();

        let mut assignment = AssignmentEntry::create(
            deposit_entry,
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed1,
        )
        .unwrap();

        let original_assignee = assignment.current_assignee();
        assert_eq!(assignment.previous_assignees.active_count(), 0);

        // Reassign to a new operator
        let new_deadline: L1Height = 200;
        let result = assignment.reassign(
            new_deadline,
            seed2,
            &notary_operators,
            &current_active_operators,
        );
        assert!(result.is_ok());

        // Verify reassignment
        assert_eq!(assignment.previous_assignees.active_count(), 1);
        assert!(assignment.previous_assignees.is_active(original_assignee));
        assert_ne!(assignment.current_assignee(), original_assignee);
    }

    #[test]
    fn test_reassign_all_operators_exhausted() {
        let mut arb = ArbitraryGenerator::new();
        let deposit_entry: DepositEntry = arb.generate();

        let withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed1: L1BlockId = arb.generate();
        let seed2: L1BlockId = arb.generate();

        // Single operator with index 0 for both the notary set and the active set.
        let notary_operators = OperatorBitmap::new_with_size(1, true);
        let current_active_operators = OperatorBitmap::new_with_size(1, true);

        let mut assignment = AssignmentEntry::create(
            deposit_entry,
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed1,
        )
        .unwrap();

        // First reassignment should work (clears previous assignees and reassigns to same operator)
        let new_deadline: L1Height = 200;
        let result = assignment.reassign(
            new_deadline,
            seed2,
            &notary_operators,
            &current_active_operators,
        );
        assert!(result.is_ok());

        // Should have cleared previous assignees and reassigned to the same operator
        assert_eq!(assignment.previous_assignees.active_count(), 0);
        assert_eq!(assignment.current_assignee(), 0); // Should be operator index 0
    }

    #[test]
    fn test_reassign_updates_deadline() {
        let mut arb = ArbitraryGenerator::new();

        let deposit_entry: DepositEntry = arb.generate();

        let withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let initial_deadline: L1Height = 100;
        let seed1: L1BlockId = arb.generate();
        let seed2: L1BlockId = arb.generate();

        // At least 2 active operators so reassignment can pick a different one.
        let notary_operators = OperatorBitmap::new_with_size(3, true);
        let current_active_operators = notary_operators.clone();

        let mut assignment = AssignmentEntry::create(
            deposit_entry,
            withdrawal_intent,
            operator_fee,
            initial_deadline,
            &notary_operators,
            &current_active_operators,
            seed1,
        )
        .unwrap();

        assert_eq!(assignment.fulfillment_deadline(), initial_deadline);

        // Reassign with a new deadline
        let new_deadline: L1Height = 250;
        let result = assignment.reassign(
            new_deadline,
            seed2,
            &notary_operators,
            &current_active_operators,
        );
        assert!(result.is_ok());

        // Verify the deadline was updated
        assert_eq!(
            assignment.fulfillment_deadline(),
            new_deadline,
            "Exec deadline should be updated to the new deadline after reassignment"
        );
    }

    #[test]
    fn test_assignment_table_basic_operations() {
        let mut table = AssignmentTable::new(100);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let mut arb = ArbitraryGenerator::new();
        let deposit_entry: DepositEntry = arb.generate();
        let withdrawal_intent: WithdrawalIntent = arb.generate();
        let operator_fee: BitcoinAmount = arb.generate();
        let fulfillment_deadline: L1Height = 100;
        let seed: L1BlockId = arb.generate();
        let notary_operators = OperatorBitmap::new_with_size(3, true);
        let current_active_operators = notary_operators.clone();

        let assignment = AssignmentEntry::create(
            deposit_entry.clone(),
            withdrawal_intent,
            operator_fee,
            fulfillment_deadline,
            &notary_operators,
            &current_active_operators,
            seed,
        )
        .unwrap();

        let deposit_idx = assignment.deposit_idx();

        // Insert assignment
        table.insert(assignment.clone());
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        // Get assignment
        let retrieved = table.get_assignment(deposit_idx);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().deposit_idx(), deposit_idx);

        // Remove assignment
        let removed = table.remove_assignment(deposit_idx);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().deposit_idx(), deposit_idx);
        assert!(table.is_empty());
    }

    #[test]
    fn test_reassign_expired_assignments() {
        let mut table = AssignmentTable::new(100);
        let mut arb = ArbitraryGenerator::new();

        // Create test data
        let current_height: L1Height = 150;
        let seed: L1BlockId = arb.generate();
        let l1_block = L1BlockCommitment::new(current_height as u32, seed);

        // Single N/N configuration shared by both deposits (notary set index 0).
        let current_active_operators = OperatorBitmap::new_with_size(5, true);
        let nn_history = NnScriptHistory::single_for_test(current_active_operators.clone());

        // Create expired assignment (deadline < current_height)
        let arb_entry1: DepositEntry = arb.generate();
        let deposit_entry1 = DepositEntry::new(arb_entry1.idx(), 0, arb_entry1.amt());

        let withdrawal_intent1: WithdrawalIntent = arb.generate();
        let operator_fee1: BitcoinAmount = arb.generate();
        let expired_deadline: L1Height = 100; // Less than current_height

        let expired_assignment = AssignmentEntry::create(
            deposit_entry1.clone(),
            withdrawal_intent1,
            operator_fee1,
            expired_deadline,
            &current_active_operators,
            &current_active_operators,
            seed,
        )
        .unwrap();

        let expired_deposit_idx = expired_assignment.deposit_idx();
        let original_assignee = expired_assignment.current_assignee();
        table.insert(expired_assignment);

        // Create non-expired assignment (deadline > current_height)
        let arb_entry2: DepositEntry = arb.generate();
        let deposit_entry2 = DepositEntry::new(arb_entry2.idx(), 0, arb_entry2.amt());

        let withdrawal_intent2: WithdrawalIntent = arb.generate();
        let operator_fee2: BitcoinAmount = arb.generate();
        let future_deadline: L1Height = 200; // Greater than current_height

        let future_assignment = AssignmentEntry::create(
            deposit_entry2.clone(),
            withdrawal_intent2,
            operator_fee2,
            future_deadline,
            &current_active_operators,
            &current_active_operators,
            seed,
        )
        .unwrap();

        let future_deposit_idx = future_assignment.deposit_idx();
        let future_original_assignee = future_assignment.current_assignee();
        table.insert(future_assignment);

        // Reassign expired assignments
        let result =
            table.reassign_expired_assignments(&nn_history, &current_active_operators, &l1_block);

        assert!(result.is_ok(), "Reassignment should succeed");

        // Check that expired assignment was reassigned
        let expired_assignment_after = table.get_assignment(expired_deposit_idx).unwrap();
        assert_eq!(
            expired_assignment_after.previous_assignees.active_count(),
            1
        );
        assert!(
            expired_assignment_after
                .previous_assignees
                .is_active(original_assignee)
        );
        // Verify the deadline was set to the new deadline
        let new_deadline: L1Height = current_height + table.assignment_duration as u32; // New absolute deadline
        assert_eq!(
            expired_assignment_after.fulfillment_deadline(),
            new_deadline,
            "Exec deadline should be set to the new deadline after reassignment"
        );

        // Check that non-expired assignment was not reassigned
        let future_assignment_after = table.get_assignment(future_deposit_idx).unwrap();
        assert_eq!(future_assignment_after.previous_assignees.active_count(), 0);
        assert_eq!(
            future_assignment_after.current_assignee(),
            future_original_assignee
        );
    }

    /// Reassigning many expired assignments in one block distributes them across the
    /// eligible operator set rather than funneling onto a single operator.
    #[test]
    fn test_reassign_expired_assignments_spread_across_operators() {
        use std::collections::HashSet;

        let mut table = AssignmentTable::new(100);
        let mut arb = ArbitraryGenerator::new();

        let current_height: L1Height = 150;
        let initial_seed: L1BlockId = arb.generate();
        let reassign_seed: L1BlockId = arb.generate();
        let l1_block = L1BlockCommitment::new(current_height, reassign_seed);

        // Ten active operators shared by every deposit so all assignments draw from the
        // same eligible pool. With 10 entries reassigned independently over 10 operators,
        // the probability of all draws colliding on a single operator is ~10^-9 — well
        // below any practical flakiness threshold while keeping the test seed-agnostic.
        let current_active_operators = OperatorBitmap::new_with_size(10, true);
        let nn_history = NnScriptHistory::single_for_test(current_active_operators.clone());

        let expired_deadline: L1Height = 100;
        let num_assignments = 10u32;
        let mut deposit_indices = Vec::new();

        for idx in 0..num_assignments {
            let arb_entry: DepositEntry = arb.generate();
            let deposit_entry = DepositEntry::new(idx, 0, arb_entry.amt());

            let withdrawal_intent: WithdrawalIntent = arb.generate();
            let operator_fee: BitcoinAmount = arb.generate();
            let assignment = AssignmentEntry::create(
                deposit_entry,
                withdrawal_intent,
                operator_fee,
                expired_deadline,
                &current_active_operators,
                &current_active_operators,
                initial_seed,
            )
            .unwrap();

            deposit_indices.push(assignment.deposit_idx());
            table.insert(assignment);
        }

        let reassigned = table
            .reassign_expired_assignments(&nn_history, &current_active_operators, &l1_block)
            .unwrap();
        assert_eq!(reassigned.len(), num_assignments as usize);

        let assignees: Vec<OperatorIdx> = deposit_indices
            .iter()
            .map(|idx| table.get_assignment(*idx).unwrap().current_assignee())
            .collect();

        let unique: HashSet<OperatorIdx> = assignees.iter().copied().collect();
        assert!(
            unique.len() > 1,
            "expected reassigned operators to spread across multiple choices, got {:?}",
            assignees,
        );
    }
}
