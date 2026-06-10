//! Bridge UTXO availability tracker for the checkpoint subprotocol.
//!
//! Bridge UTXOs all share a single denomination — fixed by the first recorded deposit and
//! enforced thereafter on every subsequent deposit. Withdrawal intents may carry any
//! non-negative integer multiple of that denomination; a multi-denomination intent
//! consumes that many UTXOs from the pool. The bridge enforces these invariants on its
//! side; the pool re-asserts them for intents arriving via OL logs.

use strata_asm_proto_bridge_v1_types::WithdrawalIntent;
use strata_btc_types::BitcoinAmount;
use zkaleido_logging as logging;

use crate::{DepositPool, errors::InvalidCheckpointPayload};

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

impl Default for DepositPool {
    fn default() -> Self {
        Self::new_empty()
    }
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

    /// Whether the pool is in its initial state — no deposits ever recorded and no
    /// denomination established. A pool that previously held UTXOs but was fully drained
    /// is NOT empty under this definition: its denomination remains locked in.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0 && self.denomination == BitcoinAmount::ZERO
    }

    /// Records a processed deposit, incrementing the available UTXO count.
    ///
    /// The first deposit into a fresh pool fixes the denomination; subsequent deposits
    /// must match it, including after the pool has been fully drained — the denomination
    /// stays locked once set. Single-denomination is a bridge-side invariant — a mismatch
    /// here indicates an upstream bug, so we log an error and skip the deposit rather
    /// than corrupt the pool's `count × denomination` accounting.
    ///
    /// NOTE: If multi-denomination deposits become supported on the bridge side, this
    /// method (and the pool's `count × denomination` model) will need to be reworked
    /// to track UTXOs per denomination.
    pub(crate) fn record(&mut self, amount: BitcoinAmount) {
        if self.is_empty() {
            self.denomination = amount;
        } else if amount != self.denomination {
            logging::error!(
                expected = ?self.denomination,
                actual = ?amount,
                "deposit amount does not match established denomination; skipping",
            );
            return;
        }
        self.count += 1;
    }

    /// Verifies that the pool can cover all withdrawal intents.
    ///
    /// Does not mutate state. Each intent's amount must be a positive integer multiple of
    /// the established denomination, and the sum of those multiples must not exceed the
    /// available UTXO count. Returns a [`VerifiedWithdrawals`] token that must be passed
    /// to [`apply_withdrawals`](Self::apply_withdrawals) to deduct the funds.
    pub(crate) fn verify_withdrawals(
        &self,
        intents: &[WithdrawalIntent],
    ) -> Result<VerifiedWithdrawals, InvalidCheckpointPayload> {
        if intents.is_empty() {
            return Ok(VerifiedWithdrawals {
                remaining_count: self.count,
            });
        }

        // Uninitialized pool: no deposits recorded, so denomination is unset. Any non-empty
        // intent set is unsatisfiable, and computing multiples would divide by zero.
        if self.count == 0 {
            return Err(InvalidCheckpointPayload::InsufficientFunds {
                available: BitcoinAmount::ZERO,
                required: BitcoinAmount::from_sat(intents.iter().map(|w| w.amt().to_sat()).sum()),
            });
        }

        let denom = self.denomination.to_sat();
        let mut required: u32 = 0;
        for intent in intents {
            let amt = intent.amt().to_sat();
            if amt == 0 || !amt.is_multiple_of(denom) {
                return Err(InvalidCheckpointPayload::DenominationMismatch {
                    expected: self.denomination,
                    actual: intent.amt(),
                });
            }
            // u32 is sufficient: pool count is u32, and we reject below if required exceeds it.
            required = required.saturating_add((amt / denom) as u32);
        }

        if required > self.count {
            return Err(InvalidCheckpointPayload::InsufficientFunds {
                available: self.total(),
                required: BitcoinAmount::from_sat(intents.iter().map(|w| w.amt().to_sat()).sum()),
            });
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
    use strata_asm_proto_bridge_v1_types::{OperatorSelection, WithdrawalIntent};
    use strata_btc_types::BitcoinAmount;

    use super::DepositPool;
    use crate::errors::InvalidCheckpointPayload;

    fn dummy_descriptor() -> Descriptor {
        Descriptor::new_p2wpkh(&[0u8; 20])
    }

    fn withdrawal(sats: u64) -> WithdrawalIntent {
        WithdrawalIntent::new(
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
    fn multi_denomination_intent_consumes_multiple_utxos() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(100_000_000);
        for _ in 0..5 {
            pool.record(denom);
        }

        let intents = vec![withdrawal(300_000_000)];
        let token = pool.verify_withdrawals(&intents).unwrap();
        pool.apply_withdrawals(token);

        assert_eq!(pool.total(), BitcoinAmount::from_sat(200_000_000));
    }

    #[test]
    fn mixed_single_and_multi_denomination_intents() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(100_000_000);
        for _ in 0..6 {
            pool.record(denom);
        }

        let intents = vec![
            withdrawal(100_000_000),
            withdrawal(300_000_000),
            withdrawal(200_000_000),
        ];
        let token = pool.verify_withdrawals(&intents).unwrap();
        pool.apply_withdrawals(token);

        assert_eq!(pool.total(), BitcoinAmount::ZERO);
    }

    #[test]
    fn multi_denomination_intent_exceeding_pool_fails() {
        let pool = {
            let mut p = DepositPool::default();
            let denom = BitcoinAmount::from_sat(100_000_000);
            for _ in 0..2 {
                p.record(denom);
            }
            p
        };

        let intents = vec![withdrawal(300_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();
        assert!(matches!(
            err,
            InvalidCheckpointPayload::InsufficientFunds { available, required }
            if available == BitcoinAmount::from_sat(200_000_000)
                && required == BitcoinAmount::from_sat(300_000_000)
        ));
    }

    #[test]
    fn non_multiple_intent_fails() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(100_000_000);
        for _ in 0..3 {
            pool.record(denom);
        }

        let intents = vec![withdrawal(150_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();
        assert!(matches!(
            err,
            InvalidCheckpointPayload::DenominationMismatch { expected, actual }
            if expected == denom && actual == BitcoinAmount::from_sat(150_000_000)
        ));
    }

    #[test]
    fn zero_amount_intent_fails() {
        let mut pool = DepositPool::default();
        let denom = BitcoinAmount::from_sat(100_000_000);
        pool.record(denom);

        let intents = vec![withdrawal(0)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();
        assert!(matches!(
            err,
            InvalidCheckpointPayload::DenominationMismatch { expected, actual }
            if expected == denom && actual == BitcoinAmount::ZERO
        ));
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
