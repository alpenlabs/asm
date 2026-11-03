use ssz_derive::{Decode, Encode};
use strata_asm_bridge_types::{
    BridgeInitConfig, OperatorIdx, SafeHarbor, SafeHarborAddress, WithdrawalIntent,
};
use strata_asm_common::logging::warn;
use strata_asm_proto_bridge_txs::{deposit::DepositInfo, errors::Mismatch};
use strata_btc_types::BitcoinAmount;
use strata_identifiers::L1BlockCommitment;

use crate::{
    assignment::{AssignmentEntry, AssignmentTable},
    deposit::{DepositEntry, DepositsTable},
    errors::{DepositValidationError, WithdrawalAssignmentError},
    operator::OperatorTable,
};

/// Main state container for the Bridge V1 subprotocol.
///
/// This structure holds all the persistent state for the bridge, including
/// operator registrations, deposit tracking, and assignment management.
#[derive(Debug, Clone, Encode, Decode)]
pub struct BridgeStateV1 {
    /// Table of registered bridge operators.
    operators: OperatorTable,

    /// Table of Bitcoin deposits managed by the bridge.
    deposits: DepositsTable,

    /// Table of operator assignments for withdrawal processing.
    assignments: AssignmentTable,

    /// The amount of bitcoin expected to be locked in the N/N multisig.
    denomination: BitcoinAmount,

    /// Amount the operator can take as fees for processing withdrawal.
    operator_fee: BitcoinAmount,

    /// Number of blocks after Deposit Request Transaction that the depositor can reclaim
    /// funds if operators fail to process the deposit.
    recovery_delay: u16,

    /// Safe harbor
    safe_harbor: SafeHarbor,
}

impl BridgeStateV1 {
    /// Creates a new bridge state with the specified configuration.
    ///
    /// Initializes all component tables as empty, creates an operator table from the provided
    /// operator public keys, and sets the expected deposit denomination and deadline duration
    /// for validation and assignment management.
    ///
    /// # Parameters
    ///
    /// - `config` - Configuration containing operator public keys, denomination, and deadline
    ///   duration
    ///
    /// # Returns
    ///
    /// A new [`BridgeStateV1`] instance.
    pub fn new(config: &BridgeInitConfig) -> Self {
        let operators = OperatorTable::from_operator_list(&config.operators);
        Self {
            operators,
            deposits: DepositsTable::new_empty(),
            assignments: AssignmentTable::new(config.assignment_duration),
            denomination: config.denomination,
            operator_fee: config.operator_fee,
            recovery_delay: config.recovery_delay,
            safe_harbor: SafeHarbor::new(SafeHarborAddress::from(&config.safe_harbor_address)),
        }
    }

    /// Returns a reference to the operator table.
    pub fn operators(&self) -> &OperatorTable {
        &self.operators
    }

    /// Returns a reference to the deposits table.
    pub fn deposits(&self) -> &DepositsTable {
        &self.deposits
    }

    /// Returns a reference to the assignments table.
    pub fn assignments(&self) -> &AssignmentTable {
        &self.assignments
    }

    /// Returns the deposit denomination.
    pub fn denomination(&self) -> &BitcoinAmount {
        &self.denomination
    }

    /// Returns the recovery delay to reclaim funds.
    pub fn recovery_delay(&self) -> u16 {
        self.recovery_delay
    }

    /// Returns a reference to the safe harbor.
    pub fn safe_harbor(&self) -> &SafeHarbor {
        &self.safe_harbor
    }

    /// Activates the safe harbor.
    pub fn activate_safe_harbor(&mut self) {
        self.safe_harbor.set_activated(true);
    }

    /// Updates the safe harbor address. Returns `false` if the safe harbor
    /// is already activated and the update was rejected.
    pub fn update_safe_harbor_address(&mut self, new_address: SafeHarborAddress) -> bool {
        if self.safe_harbor.is_activated() {
            warn!(
                ?new_address,
                "Safe harbor address update rejected: already activated"
            );
            return false;
        }
        self.safe_harbor.update_address(new_address)
    }

    /// Processes a deposit transaction by validating and adding it to the deposits table.
    ///
    /// This function takes already parsed deposit transaction information, validates it against the
    /// current state, and creates a new deposit entry in the deposits table if
    /// validation passes. Only operators that are currently active in the N/N multisig set
    /// are included as notary operators for the deposit.
    ///
    /// # Parameters
    ///
    /// - `tx` - The deposit transaction
    /// - `info` - Parsed deposit information containing amount, destination, and outpoint
    ///
    /// # Returns
    ///
    /// - `Ok(())` - If the deposit is validated and inserted successfully
    /// - `Err(DepositValidationError)` - If validation fails for any reason
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The deposit amount is zero or negative
    /// - The internal key doesn't match the current aggregated operator key
    /// - The deposit index already exists in the deposits table
    /// - The deposit index already backs a live withdrawal assignment
    pub fn add_deposit(&mut self, info: &DepositInfo) -> Result<(), DepositValidationError> {
        let deposit_idx = info.header_aux().deposit_idx();

        // Assigning a withdrawal moves its deposit out of the deposits table, so the table's own
        // uniqueness check cannot see an assigned index. Admitting one would make it the oldest
        // unassigned deposit, and the next dispatch would hit `AssignmentTable::insert`'s
        // duplicate-index panic, halting the state transition. Keeping the two tables disjoint
        // here keeps that panic unreachable whoever signed the deposit.
        if self.assignments.get_assignment(deposit_idx).is_some() {
            return Err(DepositValidationError::DepositIdxAssigned(deposit_idx));
        }

        let notary_set = self.operators.current_nn_script_index();
        let entry = DepositEntry::new(deposit_idx, notary_set, info.amt());
        self.deposits.insert_deposit(entry)?;

        Ok(())
    }

    /// Creates an [`AssignmentEntry`] assigning an operator to fulfill a withdrawal intent.
    ///
    /// The assignment logic is currently first-in-first-out: the withdrawal is backed by the
    /// oldest unassigned deposit, whose amount must match the withdrawal amount exactly. The
    /// entry is built from a clone of that deposit, with an operator selected from the currently
    /// active set and a fulfillment deadline derived from `l1_block`.
    ///
    /// This method does not mutate state: the deposit stays in the table and the returned
    /// assignment is **not** inserted. The caller is expected to log the assignment and insert it
    /// via [`insert_withdrawal_assignment`](Self::insert_withdrawal_assignment), which also
    /// removes the deposit backing it — this keeps the create/log/insert steps visible at the
    /// message-handling call site.
    ///
    /// # Errors
    ///
    /// Returns [`WithdrawalAssignmentError`] if there are no unassigned deposits, the deposit
    /// and withdrawal amounts mismatch, or no operator is eligible.
    pub fn create_withdrawal_assignment(
        &self,
        withdrawal_intent: &WithdrawalIntent,
        l1_block: &L1BlockCommitment,
    ) -> Result<AssignmentEntry, WithdrawalAssignmentError> {
        // Get the oldest deposit
        let deposit = self
            .deposits
            .oldest_deposit()
            .ok_or(WithdrawalAssignmentError::NoUnassignedDeposits)?;

        if deposit.amt() != withdrawal_intent.amt() {
            return Err(WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(
                Mismatch {
                    expected: deposit.amt().to_sat(),
                    got: withdrawal_intent.amt().to_sat(),
                },
            ));
        }

        let notary_operators = self
            .operators
            .nn_script(deposit.notary_set())
            .expect("deposit references a known N/N configuration")
            .operators();

        self.assignments.build_assignment(
            deposit.clone(),
            withdrawal_intent.clone(),
            self.operator_fee,
            notary_operators,
            self.operators.current_multisig(),
            l1_block,
        )
    }

    /// Inserts a previously [created](Self::create_withdrawal_assignment) assignment into the
    /// table, removing the deposit that backs it.
    ///
    /// # Panics
    ///
    /// Panics if the deposit referenced by the assignment is not in the deposits table.
    pub fn insert_withdrawal_assignment(&mut self, assignment: AssignmentEntry) {
        self.deposits
            .remove_deposit(assignment.deposit_idx())
            .expect("assignment consumes a deposit present in the table");
        self.assignments.insert(assignment);
    }

    /// Reassigns every assignment expired as of `current_block`, sourcing the N/N history and
    /// currently-active operator set from this state's operator table.
    ///
    /// Returns references to the reassigned entries. See
    /// `AssignmentTable::reassign_expired_assignments` for the reassignment semantics and the
    /// all-or-nothing error behaviour.
    pub fn reassign_expired_assignments(
        &mut self,
        current_block: &L1BlockCommitment,
    ) -> Result<Vec<&AssignmentEntry>, WithdrawalAssignmentError> {
        self.assignments.reassign_expired_assignments(
            self.operators.nn_history(),
            self.operators.current_multisig(),
            current_block,
        )
    }

    /// Removes an assignment by its deposit index.
    ///
    /// # Returns
    ///
    /// - `Some(AssignmentEntry)` if the assignment was found and removed
    /// - `None` if no assignment with the given deposit index exists
    pub fn remove_assignment(&mut self, deposit_idx: u32) -> Option<AssignmentEntry> {
        self.assignments.remove_assignment(deposit_idx)
    }

    /// Applies an operator set update by adding new operators and removing existing ones.
    pub fn apply_operator_set_update(
        &mut self,
        add_members: &[strata_crypto::EvenPublicKey],
        remove_members: &[OperatorIdx],
    ) {
        self.operators
            .apply_membership_changes(add_members, remove_members);
    }

    /// Removes an operator from the active multisig by deactivating them.
    ///
    /// # Panics
    ///
    /// Panics if removing this operator would result in no active operators remaining.
    pub fn remove_operator(&mut self, operator_idx: OperatorIdx) {
        self.operators
            .apply_membership_changes(&[], &[operator_idx]);
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_bridge_types::WithdrawalIntent;
    use strata_identifiers::L1BlockCommitment;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::test_utils::{add_deposits, create_test_state};

    /// Test successful withdrawal assignment creation.
    ///
    /// Verifies that withdrawal assignments are created correctly by consuming
    /// unassigned deposits and creating assignment entries. Tests the progression
    /// from multiple deposits to assignments until no deposits remain.
    #[test]
    fn test_create_withdrawal_assignment_success() {
        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();

        let count = 4;
        add_deposits(&mut state, count);

        for i in 0..count {
            let unassigned_deposit_count = state.deposits.len();
            let assigned_deposit_count = state.assignments.len();
            assert_eq!(unassigned_deposit_count as usize, count - i);
            assert_eq!(assigned_deposit_count as usize, i);

            let l1blk: L1BlockCommitment = arb.generate();
            let mut intent: WithdrawalIntent = arb.generate();
            intent.amt = state.denomination;
            let assignment = state
                .create_withdrawal_assignment(&intent, &l1blk)
                .expect("creating an assignment for a matching deposit should succeed");
            state.insert_withdrawal_assignment(assignment);

            let unassigned_deposit_count = state.deposits.len();
            let assigned_deposit_count = state.assignments.len();
            assert_eq!(unassigned_deposit_count as usize, count - i - 1);
            assert_eq!(assigned_deposit_count as usize, i + 1);
        }

        let l1blk: L1BlockCommitment = arb.generate();
        let intent: WithdrawalIntent = arb.generate();
        let res = state.create_withdrawal_assignment(&intent, &l1blk);
        assert!(res.is_err());
    }

    /// A deposit naming an index that backs a live assignment is rejected without touching state.
    ///
    /// Assignment moves the deposit out of the deposits table, so only this check stops a second
    /// deposit at the index. Without it the next dispatch would pick the new deposit and panic in
    /// `AssignmentTable::insert` on the duplicate index.
    #[test]
    fn test_add_deposit_rejects_assigned_idx() {
        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();

        let deposit = add_deposits(&mut state, 1)[0].clone();
        let deposit_idx = deposit.header_aux().deposit_idx();
        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = state.denomination;
        let l1blk: L1BlockCommitment = arb.generate();
        let assignment = state
            .create_withdrawal_assignment(&intent, &l1blk)
            .expect("creating an assignment for a matching deposit should succeed");
        state.insert_withdrawal_assignment(assignment);
        assert_eq!(state.deposits.len(), 0);

        let err = state.add_deposit(&deposit).unwrap_err();
        assert!(
            matches!(err, DepositValidationError::DepositIdxAssigned(idx) if idx == deposit_idx),
            "expected DepositIdxAssigned({deposit_idx}), got {err:?}",
        );
        assert_eq!(state.deposits.len(), 0);
        assert_eq!(state.assignments.len(), 1);
    }

    /// Once the assignment for an index is fulfilled and removed, the index is free again.
    ///
    /// Only live assignments block an index. Fulfilled ones leave no trace in state, and both
    /// tables stay disjoint either way, so reuse cannot reach the duplicate-assignment panic.
    #[test]
    fn test_add_deposit_allows_idx_after_assignment_removed() {
        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();

        let deposit = add_deposits(&mut state, 1)[0].clone();
        let deposit_idx = deposit.header_aux().deposit_idx();
        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = state.denomination;
        let l1blk: L1BlockCommitment = arb.generate();
        let assignment = state
            .create_withdrawal_assignment(&intent, &l1blk)
            .expect("creating an assignment for a matching deposit should succeed");
        state.insert_withdrawal_assignment(assignment);
        state
            .remove_assignment(deposit_idx)
            .expect("assignment was just inserted");

        state
            .add_deposit(&deposit)
            .expect("an index with no live deposit or assignment is free");
        assert!(state.deposits.get_deposit(deposit_idx).is_some());
    }

    /// Test withdrawal assignment creation failure scenarios.
    ///
    /// Verifies that withdrawal assignment creation fails when there's a mismatch
    /// between the deposit amount and withdrawal command amount.
    #[test]
    fn test_create_withdrawal_assignment_failure() {
        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();

        let count = 1;
        let deposit = add_deposits(&mut state, count)[0].clone();

        let l1blk: L1BlockCommitment = arb.generate();
        let intent: WithdrawalIntent = arb.generate();
        let err = state
            .create_withdrawal_assignment(&intent, &l1blk)
            .unwrap_err();
        assert!(matches!(
            err,
            WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(..)
        ));
        if let WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(mismatch) = err {
            assert_eq!(mismatch.got, intent.amt.to_sat());
            assert_eq!(mismatch.expected, deposit.amt().to_sat());
        }

        // A failed creation must not mutate state: the deposit stays in the table.
        assert_eq!(state.deposits.len(), 1);
    }
}
