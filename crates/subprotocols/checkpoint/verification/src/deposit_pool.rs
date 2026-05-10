//! Bridge UTXO availability tracker for the checkpoint subprotocol.
//!
//! All deposits and withdrawal intents must share a single denomination — fixed by the
//! first recorded deposit and enforced thereafter. The bridge enforces this invariant on
//! its side; the pool re-asserts it for intents arriving via OL logs.

use ssz_derive::{Decode, Encode};
use strata_asm_proto_bridge_v1_types::WithdrawOutput;
use strata_btc_types::BitcoinAmount;

use crate::errors::InvalidCheckpointPayload;

/// Pool of bridge UTXOs available to honor withdrawals.
///
/// Defaults to empty (denomination = `ZERO`, count = 0). The denomination is fixed by the
/// first recorded deposit; from then on, every deposit and withdrawal intent must match it.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct DepositPool {
    /// Bridge deposit denomination. Trivially zero until the first deposit fixes it.
    denomination: BitcoinAmount,

    /// Count of bridge UTXOs that have been processed but not yet consumed by withdrawals.
    count: u32,
}

impl Default for DepositPool {
    fn default() -> Self {
        Self::new_empty()
    }
}

/// Opaque proof token for a verified set of withdrawal intents.
///
/// Produced by [`DepositPool::verify_withdrawals`] and consumed by
/// [`DepositPool::apply_withdrawals`], enforcing at the type level that deduction can only happen
/// after successful verification. Has no public constructor or accessors and is neither [`Clone`]
/// nor [`Copy`], so each verification yields exactly one deduction.
#[derive(Debug)]
pub(crate) struct VerifiedWithdrawals {
    remaining_count: u32,
}

impl DepositPool {
    /// Creates an empty pool with no recorded deposits and an unset denomination.
    pub(crate) fn new_empty() -> Self {
        Self {
            denomination: BitcoinAmount::ZERO,
            count: 0,
        }
    }

    /// Total available value across all unspent bridge UTXOs.
    pub(crate) fn total(&self) -> BitcoinAmount {
        BitcoinAmount::from_sat(self.denomination.to_sat() * self.count as u64)
    }

    /// Records a processed deposit, incrementing the available UTXO count.
    ///
    /// The first deposit (when `count == 0`) fixes the denomination; subsequent deposits
    /// debug-assert that the amount matches it. Single-denomination is a bridge-side
    /// invariant — a mismatch here indicates an upstream bug.
    pub(crate) fn record(&mut self, amount: BitcoinAmount) {
        if self.count == 0 {
            self.denomination = amount;
        } else {
            debug_assert_eq!(
                amount, self.denomination,
                "deposits must match the established denomination"
            );
        }
        self.count += 1;
    }

    /// Verifies that the pool can cover all withdrawal intents.
    ///
    /// Does not mutate state. The available UTXO count must cover the number of intents,
    /// and each intent's amount must equal the established denomination. Returns a
    /// [`VerifiedWithdrawals`] token that must be passed to
    /// [`apply_withdrawals`](Self::apply_withdrawals) to deduct the funds.
    pub(crate) fn verify_withdrawals(
        &self,
        intents: &[WithdrawOutput],
    ) -> Result<VerifiedWithdrawals, InvalidCheckpointPayload> {
        if intents.is_empty() {
            return Ok(VerifiedWithdrawals {
                remaining_count: self.count,
            });
        }

        // Count check first: an empty pool naturally fails here with `available = ZERO`,
        // so no separate "uninitialized" branch is needed.
        let required = intents.len() as u32;
        if required > self.count {
            return Err(InvalidCheckpointPayload::InsufficientFunds {
                available: self.total(),
                required: BitcoinAmount::from_sat(intents.iter().map(|w| w.amt().to_sat()).sum()),
            });
        }

        for intent in intents {
            if intent.amt() != self.denomination {
                return Err(InvalidCheckpointPayload::DenominationMismatch {
                    expected: self.denomination,
                    actual: intent.amt(),
                });
            }
        }

        Ok(VerifiedWithdrawals {
            remaining_count: self.count - required,
        })
    }

    /// Applies a pre-verified deduction to the pool.
    pub(crate) fn apply_withdrawals(&mut self, token: VerifiedWithdrawals) {
        self.count = token.remaining_count;
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;
    use strata_asm_proto_bridge_v1_types::{OperatorSelection, WithdrawOutput};
    use strata_btc_types::BitcoinAmount;

    use super::DepositPool;
    use crate::errors::InvalidCheckpointPayload;

    fn dummy_descriptor() -> Descriptor {
        Descriptor::new_p2wpkh(&[0u8; 20])
    }

    fn withdrawal(sats: u64) -> WithdrawOutput {
        WithdrawOutput::new(
            dummy_descriptor(),
            BitcoinAmount::from_sat(sats),
            OperatorSelection::any(),
        )
    }

    #[test]
    fn empty_pool_total_is_zero() {
        let pool = DepositPool::default();
        assert_eq!(pool.total(), BitcoinAmount::ZERO);
    }

    #[test]
    fn record_sets_denomination_and_counts() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(500_000_000);

        pool.record(denom);
        pool.record(denom);
        pool.record(denom);

        assert_eq!(pool.total(), BitcoinAmount::from_sat(1_500_000_000));
    }

    #[test]
    fn deduct_exact_denomination_match() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(500_000_000);

        pool.record(denom);
        pool.record(denom);

        let intents = vec![withdrawal(500_000_000)];
        let token = pool.verify_withdrawals(&intents).unwrap();
        pool.apply_withdrawals(token);
        assert_eq!(pool.total(), BitcoinAmount::from_sat(500_000_000));
    }

    #[test]
    fn denomination_mismatch_fails() {
        let mut pool = DepositPool::default();
        pool.record(BitcoinAmount::from_sat(1_000_000_000));

        let intents = vec![withdrawal(500_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::DenominationMismatch { expected, actual }
            if expected == BitcoinAmount::from_sat(1_000_000_000)
                && actual == BitcoinAmount::from_sat(500_000_000)
        ));

        assert_eq!(pool.total(), BitcoinAmount::from_sat(1_000_000_000));
    }

    #[test]
    fn insufficient_count_fails() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(500_000_000);
        pool.record(denom);

        let intents = vec![withdrawal(500_000_000), withdrawal(500_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::InsufficientFunds { available, required }
            if available == BitcoinAmount::from_sat(500_000_000)
                && required == BitcoinAmount::from_sat(1_000_000_000)
        ));

        assert_eq!(pool.total(), BitcoinAmount::from_sat(500_000_000));
    }

    #[test]
    fn withdrawal_against_empty_pool_fails() {
        let pool = DepositPool::default();
        let intents = vec![withdrawal(500_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::InsufficientFunds { available, required }
            if available == BitcoinAmount::ZERO
                && required == BitcoinAmount::from_sat(500_000_000)
        ));
    }

    #[test]
    fn batch_withdrawal_same_denomination() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(100_000_000);

        for _ in 0..5 {
            pool.record(denom);
        }

        let intents = vec![
            withdrawal(100_000_000),
            withdrawal(100_000_000),
            withdrawal(100_000_000),
        ];
        let token = pool.verify_withdrawals(&intents).unwrap();
        pool.apply_withdrawals(token);
        assert_eq!(pool.total(), BitcoinAmount::from_sat(200_000_000));
    }

    #[test]
    fn empty_intents_succeed_on_empty_pool() {
        let pool = DepositPool::default();
        pool.verify_withdrawals(&[]).unwrap();
    }

    #[test]
    fn empty_intents_succeed_with_deposits() {
        let mut pool = DepositPool::default();
        pool.record(BitcoinAmount::from_sat(500_000_000));

        let token = pool.verify_withdrawals(&[]).unwrap();
        pool.apply_withdrawals(token);
        assert_eq!(pool.total(), BitcoinAmount::from_sat(500_000_000));
    }
}
