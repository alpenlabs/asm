use ssz_derive::{Decode, Encode};
use strata_asm_common::logging::{debug, info, warn};
use strata_asm_params::BridgeV1InitConfig;
use strata_asm_proto_bridge_v1_txs::{deposit::DepositInfo, errors::Mismatch};
use strata_asm_proto_bridge_v1_types::{
    OperatorIdx, SafeHarbour, SafeHarbourAddress, WithdrawalIntent,
};
use strata_btc_types::BitcoinAmount;
use strata_identifiers::L1BlockCommitment;

use crate::{
    errors::{DepositValidationError, WithdrawalAssignmentError},
    state::{
        assignment::{AssignmentEntry, AssignmentTable},
        deposit::{DepositEntry, DepositsTable},
        operator::OperatorTable,
    },
};

/// Main state container for the Bridge V1 subprotocol.
///
/// This structure holds all the persistent state for the bridge, including
/// operator registrations, deposit tracking, and assignment management.
#[derive(Debug, Clone, Encode, Decode)]
pub struct BridgeV1State {
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

    /// Safe harbour
    safe_harbour: SafeHarbour,
}

impl BridgeV1State {
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
    /// A new [`BridgeV1State`] instance.
    pub fn new(config: &BridgeV1InitConfig) -> Self {
        let operators = OperatorTable::from_operator_list(&config.operators);
        Self {
            operators,
            deposits: DepositsTable::new_empty(),
            assignments: AssignmentTable::new(config.assignment_duration),
            denomination: config.denomination,
            operator_fee: config.operator_fee,
            recovery_delay: config.recovery_delay,
            safe_harbour: SafeHarbour::new(config.safe_harbour_address.clone()),
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

    /// Returns a reference to the safe harbour.
    pub fn safe_harbour(&self) -> &SafeHarbour {
        &self.safe_harbour
    }

    /// Activates the safe harbour.
    pub fn activate_safe_harbour(&mut self) {
        self.safe_harbour.set_activated(true);
    }

    /// Updates the safe harbour address. Returns `false` if the safe harbour
    /// is already activated and the update was rejected.
    pub fn update_safe_harbour_address(&mut self, new_address: SafeHarbourAddress) -> bool {
        if self.safe_harbour.is_activated() {
            warn!(
                ?new_address,
                "Safe harbour address update rejected: already activated"
            );
            return false;
        }
        self.safe_harbour.update_address(new_address)
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
    pub fn add_deposit(&mut self, info: &DepositInfo) -> Result<(), DepositValidationError> {
        let notary_operators = self.operators.current_multisig().clone();
        let entry = DepositEntry::new(
            info.header_aux().deposit_idx(),
            notary_operators,
            info.amt(),
        )?;
        self.deposits.insert_deposit(entry)?;

        Ok(())
    }

    /// Adds a new withdrawal assignment to the assignments table.
    ///
    /// This retrieves the oldest unassigned deposit UTXO, validates that its amount matches
    /// the withdrawal amount, and records the configured operator fee on the assignment.
    /// The assignment is then added to the table with operators randomly selected from the
    /// currently active operators.
    ///
    /// # Parameters
    ///
    /// - `withdrawal_intent` - destination, amount, and the user's preferred operator
    /// - `l1_block` - The L1 block commitment used for operator selection and deadline calculation
    ///
    /// # Returns
    ///
    /// - `Ok(())` - If the withdrawal assignment was successfully added
    /// - `Err(WithdrawalAssignmentError)` - If no unassigned deposits, amounts mismatch, or adding
    ///   new assignment fails
    pub fn create_withdrawal_assignment(
        &mut self,
        withdrawal_intent: &WithdrawalIntent,
        l1_block: &L1BlockCommitment,
    ) -> Result<(), WithdrawalAssignmentError> {
        // Get the oldest deposit
        let deposit = self
            .deposits
            .remove_oldest_deposit()
            .ok_or(WithdrawalAssignmentError::NoUnassignedDeposits)?;

        if deposit.amt() != withdrawal_intent.amt() {
            return Err(WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(
                Mismatch {
                    expected: deposit.amt().to_sat(),
                    got: withdrawal_intent.amt().to_sat(),
                },
            ));
        }

        let selected_operator = withdrawal_intent.selected_operator();
        let deposit_idx = deposit.idx();
        let amount_sat = deposit.amt().to_sat();
        let result = self.assignments.add_new_assignment(
            deposit,
            withdrawal_intent.clone(),
            self.operator_fee,
            self.operators.current_multisig(),
            l1_block,
        );

        if result.is_ok() {
            let assignment = self
                .assignments
                .get_assignment(deposit_idx)
                .expect("assignment must exist after successful insertion");
            info!(
                deposit_idx,
                assignee = assignment.current_assignee(),
                amount_sat,
                fulfillment_deadline = assignment.fulfillment_deadline(),
                selected_operator = %selected_operator,
                "Created withdrawal assignment",
            );
        }

        result
    }

    /// Decomposes a batch withdrawal into N individual assignments.
    ///
    /// Splits `withdrawal_intent.amt()` into `N = amt / denomination` calls to
    /// [`create_withdrawal_assignment`](Self::create_withdrawal_assignment), each with the
    /// bridge denomination and the same destination and operator selection.
    pub fn create_batch_withdrawal_assignments(
        &mut self,
        withdrawal_intent: &WithdrawalIntent,
        l1_block: &L1BlockCommitment,
    ) -> Result<(), WithdrawalAssignmentError> {
        let amt = withdrawal_intent.amt().to_sat();
        let denom = self.denomination.to_sat();

        if !amt.is_multiple_of(denom) {
            return Err(WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(
                Mismatch {
                    expected: denom,
                    got: amt,
                },
            ));
        }

        let n = amt / denom;
        debug!(
            total_amount_sat = amt,
            denomination_sat = denom,
            assignments = n,
            "Decomposing batch withdrawal"
        );
        let single_intent = WithdrawalIntent::new(
            withdrawal_intent.destination().clone(),
            self.denomination,
            withdrawal_intent.selected_operator(),
        );

        for _ in 0..n {
            self.create_withdrawal_assignment(&single_intent, l1_block)?;
        }

        Ok(())
    }

    /// Processes all expired assignments by reassigning them to new operators.
    ///
    /// This function iterates through all assignments, identifies those that have expired
    /// based on the current Bitcoin block height, and attempts to reassign them to new
    /// operators that haven't been previously assigned to the same withdrawal.
    ///
    /// # Parameters
    ///
    /// - `current_block` - The current L1 block commitment containing height and block hash
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u32>)` - Vector of deposit indices that were successfully reassigned
    /// - `Err(WithdrawalAssignmentError)` - If any reassignment fails
    ///
    /// # Notes
    ///
    /// If a reassignment fails for any expired assignment (e.g., no eligible operators
    /// remaining), the function returns an error and stops processing. Successfully
    /// reassigned deposits before the error are returned in the error context if needed.
    pub fn reassign_expired_assignments(
        &mut self,
        current_block: &L1BlockCommitment,
    ) -> Result<Vec<u32>, WithdrawalAssignmentError> {
        let reassigned_deposits = self
            .assignments
            .reassign_expired_assignments(self.operators.current_multisig(), current_block)?;

        for deposit_idx in &reassigned_deposits {
            if let Some(assignment) = self.assignments.get_assignment(*deposit_idx) {
                info!(
                    deposit_idx,
                    assignee = assignment.current_assignee(),
                    fulfillment_deadline = assignment.fulfillment_deadline(),
                    l1_height = current_block.height(),
                    "Reassigned expired withdrawal assignment",
                );
            }
        }

        Ok(reassigned_deposits)
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
    use strata_asm_proto_bridge_v1_types::WithdrawalIntent;
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
            let res = state.create_withdrawal_assignment(&intent, &l1blk);
            assert!(res.is_ok());

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
    }

    #[test]
    fn test_create_batch_withdrawal_assignments_success() {
        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();

        add_deposits(&mut state, 5);

        let l1blk: L1BlockCommitment = arb.generate();
        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = BitcoinAmount::from_sat(state.denomination.to_sat() * 3);

        state
            .create_batch_withdrawal_assignments(&intent, &l1blk)
            .unwrap();

        assert_eq!(state.assignments.len(), 3);
        assert_eq!(state.deposits.len(), 2);
    }

    #[test]
    fn test_create_batch_withdrawal_assignments_non_multiple_fails() {
        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();

        add_deposits(&mut state, 2);

        let l1blk: L1BlockCommitment = arb.generate();
        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = BitcoinAmount::from_sat(state.denomination.to_sat() + 1);

        let err = state
            .create_batch_withdrawal_assignments(&intent, &l1blk)
            .unwrap_err();

        assert!(matches!(
            err,
            WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(..)
        ));
        if let WithdrawalAssignmentError::DepositWithdrawalAmountMismatch(mismatch) = err {
            assert_eq!(mismatch.expected, state.denomination.to_sat());
            assert_eq!(mismatch.got, intent.amt.to_sat());
        }

        assert_eq!(state.assignments.len(), 0);
        assert_eq!(state.deposits.len(), 2);
    }
}
