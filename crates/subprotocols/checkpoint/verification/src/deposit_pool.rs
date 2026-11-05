//! Bridge UTXO availability tracker for the checkpoint subprotocol.
//!
//! Bridge UTXOs all share a single denomination — fixed by the first recorded deposit and
//! enforced thereafter on every subsequent deposit. Withdrawal intents may carry any
//! non-negative integer multiple of that denomination; a multi-denomination intent
//! consumes that many UTXOs from the pool. The bridge enforces these invariants on its
//! side; the pool re-asserts them for intents arriving via OL logs.

use strata_asm_bridge_types::WithdrawalIntent;
use strata_btc_types::BitcoinAmount;
use zkaleido_logging as logging;

use crate::{DepositPool, errors::InvalidCheckpointPayload};

fn bitcoin_amount(sats: u64) -> BitcoinAmount {
    BitcoinAmount::try_from(sats).expect("amount must not exceed the Bitcoin money supply")
}

fn total_withdrawal_amount(
    intents: &[WithdrawalIntent],
) -> Result<BitcoinAmount, InvalidCheckpointPayload> {
    // A u64 overflow is far past the money supply, so it fails the same way.
    let sats = intents
        .iter()
        .try_fold(0u64, |acc, intent| acc.checked_add(intent.amt().to_sat()))
        .ok_or(InvalidCheckpointPayload::WithdrawalTotalTooLarge)?;
    BitcoinAmount::try_from(sats).map_err(|_| InvalidCheckpointPayload::WithdrawalTotalTooLarge)
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

impl Default for DepositPool {
    fn default() -> Self {
        Self::new_empty()
    }
}

impl DepositPool {
    /// Creates an empty pool with no recorded deposits and an unset denomination.
    pub(crate) fn new_empty() -> Self {
        Self {
            denomination: BitcoinAmount::default(),
            count: 0,
        }
    }

    /// Total available value across all unspent bridge UTXOs.
    pub(crate) fn total(&self) -> BitcoinAmount {
        let sats = self
            .denomination
            .to_sat()
            .checked_mul(self.count as u64)
            .expect("deposit pool total must fit in u64");
        bitcoin_amount(sats)
    }

    /// Whether the pool is in its initial state — no deposits ever recorded and no
    /// denomination established. A pool that previously held UTXOs but was fully drained
    /// is NOT empty under this definition: its denomination remains locked in.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0 && self.denomination == BitcoinAmount::default()
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
                expected_sat = self.denomination.to_sat(),
                actual_sat = amount.to_sat(),
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
                available: BitcoinAmount::default(),
                required: total_withdrawal_amount(intents)?,
            });
        }

        // `None` once the sum overflows u64, which is more UTXOs than any u32 pool holds.
        let mut required = Some(0u64);
        for intent in intents {
            let units = intent
                .denomination_units(self.denomination)
                .filter(|&n| n > 0)
                .ok_or(InvalidCheckpointPayload::DenominationMismatch {
                    expected: self.denomination,
                    actual: intent.amt(),
                })?;
            required = required.and_then(|sum| sum.checked_add(units));
        }

        match required {
            Some(required) if required <= u64::from(self.count) => Ok(VerifiedWithdrawals {
                remaining_count: self.count
                    - u32::try_from(required).expect("required <= count, which is a u32"),
            }),
            _ => Err(InvalidCheckpointPayload::InsufficientFunds {
                available: self.total(),
                required: total_withdrawal_amount(intents)?,
            }),
        }
    }

    /// Applies a pre-verified deduction to the pool.
    pub(crate) fn apply_withdrawals(&mut self, token: VerifiedWithdrawals) {
        self.count = token.remaining_count;
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;
    use strata_asm_bridge_types::{OperatorSelection, WithdrawalIntent};
    use strata_asm_checkpoint_types::MAX_OL_LOGS_PER_CHECKPOINT;
    use strata_btc_types::BitcoinAmount;

    use super::{DepositPool, bitcoin_amount};
    use crate::errors::InvalidCheckpointPayload;

    const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

    fn dummy_descriptor() -> Descriptor {
        Descriptor::new_p2wpkh(&[0u8; 20])
    }

    fn withdrawal(sats: u64) -> WithdrawalIntent {
        WithdrawalIntent::new(
            dummy_descriptor(),
            bitcoin_amount(sats),
            OperatorSelection::any(),
        )
    }

    #[test]
    fn empty_pool_total_is_zero() {
        let pool = DepositPool::default();
        assert_eq!(pool.total(), BitcoinAmount::default());
    }

    #[test]
    fn record_sets_denomination_and_counts() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(500_000_000);

        pool.record(denom);
        pool.record(denom);
        pool.record(denom);

        assert_eq!(pool.total(), bitcoin_amount(1_500_000_000));
    }

    #[test]
    fn deduct_exact_denomination_match() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(500_000_000);

        pool.record(denom);
        pool.record(denom);

        let intents = vec![withdrawal(500_000_000)];
        let token = pool.verify_withdrawals(&intents).unwrap();
        pool.apply_withdrawals(token);
        assert_eq!(pool.total(), bitcoin_amount(500_000_000));
    }

    #[test]
    fn denomination_mismatch_fails() {
        let mut pool = DepositPool::default();
        pool.record(bitcoin_amount(1_000_000_000));

        let intents = vec![withdrawal(500_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::DenominationMismatch { expected, actual }
            if expected == bitcoin_amount(1_000_000_000)
                && actual == bitcoin_amount(500_000_000)
        ));

        assert_eq!(pool.total(), bitcoin_amount(1_000_000_000));
    }

    #[test]
    fn insufficient_count_fails() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(500_000_000);
        pool.record(denom);

        let intents = vec![withdrawal(500_000_000), withdrawal(500_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::InsufficientFunds { available, required }
            if available == bitcoin_amount(500_000_000)
                && required == bitcoin_amount(1_000_000_000)
        ));

        assert_eq!(pool.total(), bitcoin_amount(500_000_000));
    }

    #[test]
    fn withdrawal_against_empty_pool_fails() {
        let pool = DepositPool::default();
        let intents = vec![withdrawal(500_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::InsufficientFunds { available, required }
            if available == BitcoinAmount::default()
                && required == bitcoin_amount(500_000_000)
        ));
    }

    #[test]
    fn withdrawal_total_above_money_supply_is_rejected() {
        let pool = DepositPool::default();
        let intents = vec![withdrawal(MAX_MONEY_SATS), withdrawal(MAX_MONEY_SATS)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();

        assert!(matches!(
            err,
            InvalidCheckpointPayload::WithdrawalTotalTooLarge
        ));
    }

    #[test]
    fn batch_withdrawal_same_denomination() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(100_000_000);

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
        assert_eq!(pool.total(), bitcoin_amount(200_000_000));
    }

    #[test]
    fn empty_intents_succeed_on_empty_pool() {
        let pool = DepositPool::default();
        pool.verify_withdrawals(&[]).unwrap();
    }

    #[test]
    fn multi_denomination_intent_consumes_multiple_utxos() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(100_000_000);
        for _ in 0..5 {
            pool.record(denom);
        }

        let intents = vec![withdrawal(300_000_000)];
        let token = pool.verify_withdrawals(&intents).unwrap();
        pool.apply_withdrawals(token);

        assert_eq!(pool.total(), bitcoin_amount(200_000_000));
    }

    #[test]
    fn mixed_single_and_multi_denomination_intents() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(100_000_000);
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

        assert_eq!(pool.total(), BitcoinAmount::default());
    }

    #[test]
    fn multi_denomination_intent_exceeding_pool_fails() {
        let pool = {
            let mut p = DepositPool::default();
            let denom = bitcoin_amount(100_000_000);
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
            if available == bitcoin_amount(200_000_000)
                && required == bitcoin_amount(300_000_000)
        ));
    }

    #[test]
    fn non_multiple_intent_fails() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(100_000_000);
        for _ in 0..3 {
            pool.record(denom);
        }

        let intents = vec![withdrawal(150_000_000)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();
        assert!(matches!(
            err,
            InvalidCheckpointPayload::DenominationMismatch { expected, actual }
            if expected == denom && actual == bitcoin_amount(150_000_000)
        ));
    }

    #[test]
    fn zero_amount_intent_fails() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(100_000_000);
        pool.record(denom);

        let intents = vec![withdrawal(0)];
        let err = pool.verify_withdrawals(&intents).unwrap_err();
        assert!(matches!(
            err,
            InvalidCheckpointPayload::DenominationMismatch { expected, actual }
            if expected == denom && actual == BitcoinAmount::default()
        ));
    }

    /// An intent worth `2^32` or more UTXOs must be rejected, not truncated to u32.
    ///
    /// At a 1000 sat denomination these amounts are under the money supply, so they reach
    /// the pool. A u32 cast turns `2^32` UTXOs into 0 and `2^32 + 1` into 1, both of which a
    /// single-UTXO pool would accept while the bridge dispatches the full count.
    #[test]
    fn intent_of_u32_overflowing_utxo_count_is_rejected() {
        let mut pool = DepositPool::default();
        let denom = bitcoin_amount(1_000);
        pool.record(denom);

        for utxos in [1u64 << 32, (1u64 << 32) + 1] {
            let intents = vec![withdrawal(utxos * 1_000)];
            let err = pool.verify_withdrawals(&intents).unwrap_err();

            assert!(matches!(
                err,
                InvalidCheckpointPayload::InsufficientFunds { available, required }
                if available == denom && required == bitcoin_amount(utxos * 1_000)
            ));
        }
    }

    /// Intents totalling `2^64 + 1` UTXOs at a 1 sat denomination are rejected, not wrapped.
    ///
    /// Every intent is under the money supply and the count fits one checkpoint. Summing
    /// per-intent UTXO counts in u64 wraps this total to 1, which a one-UTXO pool would
    /// accept in release builds. Debug builds would panic before the proof is checked.
    #[test]
    fn aggregate_wrapping_u64_at_one_sat_denomination_is_rejected() {
        let mut pool = DepositPool::default();
        pool.record(bitcoin_amount(1));

        let target = (1u128 << 64) + 1;
        let full = u64::try_from(target / u128::from(MAX_MONEY_SATS)).unwrap();
        let rest = u64::try_from(target % u128::from(MAX_MONEY_SATS)).unwrap();
        let mut intents = vec![withdrawal(MAX_MONEY_SATS); full as usize];
        intents.push(withdrawal(rest));
        assert!(intents.len() as u64 <= MAX_OL_LOGS_PER_CHECKPOINT);

        let err = pool.verify_withdrawals(&intents).unwrap_err();
        assert!(matches!(
            err,
            InvalidCheckpointPayload::WithdrawalTotalTooLarge
        ));
    }

    /// A withdrawal of exactly the whole pool is accepted and drains it, including at the
    /// largest count the u32 field can hold. One more UTXO is rejected.
    #[test]
    fn withdrawal_of_whole_pool_drains_it_at_u32_max() {
        let mut pool = DepositPool {
            denomination: bitcoin_amount(1),
            count: u32::MAX,
        };

        let too_much = vec![withdrawal(u64::from(u32::MAX) + 1)];
        assert!(matches!(
            pool.verify_withdrawals(&too_much).unwrap_err(),
            InvalidCheckpointPayload::InsufficientFunds { .. }
        ));

        let exact = vec![withdrawal(u64::from(u32::MAX))];
        let token = pool.verify_withdrawals(&exact).unwrap();
        pool.apply_withdrawals(token);
        assert_eq!(pool.count, 0);
    }

    /// The pool must deduct exactly as many UTXOs as the bridge assigns for the same intents,
    /// or the two drift apart and the bridge runs out of deposits mid-dispatch.
    #[test]
    fn deducted_utxos_match_bridge_decompose() {
        for denom_sats in [1, 1_000, 100_000_000] {
            let denom = bitcoin_amount(denom_sats);
            let mut pool = DepositPool::default();
            for _ in 0..20 {
                pool.record(denom);
            }

            let intents: Vec<_> = [1, 3, 7]
                .into_iter()
                .map(|n| withdrawal(n * denom_sats))
                .collect();
            let dispatched: usize = intents
                .iter()
                .map(|intent| intent.decompose(denom).unwrap().count())
                .sum();

            let before = pool.count;
            let token = pool.verify_withdrawals(&intents).unwrap();
            pool.apply_withdrawals(token);
            assert_eq!((before - pool.count) as usize, dispatched);
        }
    }

    #[test]
    fn empty_intents_succeed_with_deposits() {
        let mut pool = DepositPool::default();
        pool.record(bitcoin_amount(500_000_000));

        let token = pool.verify_withdrawals(&[]).unwrap();
        pool.apply_withdrawals(token);
        assert_eq!(pool.total(), bitcoin_amount(500_000_000));
    }
}
