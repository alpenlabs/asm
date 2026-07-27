//! Test utilities for constructing and populating bridge state.

use rand::Rng;
use strata_asm_proto_bridge_txs::{deposit::DepositInfo, test_utils::create_test_operators};
use strata_asm_proto_bridge_types::{BridgeInitConfig, WithdrawalIntent};
use strata_btc_types::BitcoinAmount;
use strata_crypto::EvenSecretKey;
use strata_identifiers::L1BlockCommitment;
use strata_test_utils_arb::ArbitraryGenerator;

use crate::bridge::BridgeStateV1;

/// Helper function to create a test bridge state and associated operator keys.
///
/// This function initializes a `BridgeStateV1` with a randomly generated number of operators
/// (between 2 and 5), a fixed denomination, and an assignment duration. It returns the
/// initialized state along with the private keys of the operators, which can be used for
/// signing test transactions.
///
/// # Returns
///
/// - `(BridgeStateV1, Vec<EvenSecretKey>)` - A tuple containing the initialized bridge state and a
///   vector of `EvenSecretKey` for the operators.
pub fn create_test_state() -> (BridgeStateV1, Vec<EvenSecretKey>) {
    let mut rng = rand::thread_rng();
    let num_operators = rng.gen_range(2..=5);
    let (privkeys, operators) = create_test_operators(num_operators);
    let denomination = BitcoinAmount::from_sat(1_000_000);
    let config = BridgeInitConfig {
        denomination,
        operators,
        assignment_duration: 144, // ~24 hours
        operator_fee: BitcoinAmount::from_sat(100_000),
        recovery_delay: 1008,
        safe_harbour_address: ArbitraryGenerator::new().generate(),
    };
    let bridge_state = BridgeStateV1::new(&config);
    (bridge_state, privkeys)
}

/// Helper function to add multiple test deposits to the bridge state.
///
/// Creates the specified number of deposits with randomly generated deposit info,
/// but ensures each deposit uses the bridge's expected denomination amount.
/// Each deposit is processed through the full validation pipeline.
///
/// # Parameters
///
/// - `state` - Mutable reference to the bridge state to add deposits to
/// - `count` - Number of deposits to create and add
pub fn add_deposits(state: &mut BridgeStateV1, count: usize) -> Vec<DepositInfo> {
    let mut arb = ArbitraryGenerator::new();
    let mut infos = Vec::new();
    for _ in 0..count {
        let mut info: DepositInfo = arb.generate();
        info.set_amt(*state.denomination());
        state.add_deposit(&info).unwrap();
        infos.push(info);
    }
    infos
}

/// Helper function to add deposits and immediately create withdrawal assignments.
///
/// This is a convenience function that combines deposit creation with assignment
/// creation. For each deposit added, it creates a corresponding withdrawal intent
/// and assignment. This simulates a complete deposit-to-assignment flow for testing.
///
/// # Parameters
///
/// - `state` - Mutable reference to the bridge state
/// - `count` - Number of deposit-assignment pairs to create
pub fn add_deposits_and_assignments(state: &mut BridgeStateV1, count: usize) {
    add_deposits(state, count);
    let mut arb = ArbitraryGenerator::new();
    for _ in 0..count {
        let l1blk: L1BlockCommitment = arb.generate();
        let mut intent: WithdrawalIntent = arb.generate();
        intent.amt = *state.denomination();
        let assignment = state.create_withdrawal_assignment(&intent, &l1blk).unwrap();
        state.insert_withdrawal_assignment(assignment);
    }
}
