//! Converting the released checkpoint state into this crate's layout.
//!
//! The conversion lives here, in the crate that defines the *new* layout, and
//! depends on the crate that defines the old one. That direction matters: were
//! it reversed, every frozen layout would accrete a dependency on each layout
//! that ever succeeded it, and a crate that must never change would be edited
//! on every future upgrade.
//!
//! Deciding *when* to convert is not this module's job. The framework compares
//! the state's own codec versions against the specification's schema, calls the
//! conversion only when they differ, and verifies the result — see
//! `strata_asm_common::prepare_state`.

use strata_btc_types::BitcoinAmount;
use strata_checkpoint_verification_v0::CheckpointState as CheckpointStateV0;
use thiserror::Error;

use crate::{CheckpointState, DepositPool};

/// Failure to convert released checkpoint state into the current layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CheckpointMigrationError {
    /// The released denomination is outside the money supply the current
    /// [`BitcoinAmount`] admits.
    ///
    /// The released amount type constructed and decoded without a money-supply
    /// bound, so such a value could in principle be committed; the current type
    /// rejects it. A denomination is set from a deposit output and so is bounded
    /// by Bitcoin consensus in practice, but the conversion reports rather than
    /// clamping, because clamping a denomination would move funds.
    #[error("released deposit denomination {sats} sat is outside the money supply")]
    DenominationOutsideMoneySupply {
        /// The satoshi count found in the released state.
        sats: u64,
    },

    /// The denomination is valid by itself, but the value represented by all
    /// released deposit UTXOs exceeds the Bitcoin money supply.
    #[error(
        "released deposit pool total {total_sats} sat ({denomination_sats} sat x {count}) is outside the money supply"
    )]
    DepositPoolTotalOutsideMoneySupply {
        /// Denomination of one released deposit UTXO.
        denomination_sats: u64,
        /// Number of released deposit UTXOs.
        count: u32,
        /// Aggregate value represented by the pool.
        total_sats: u128,
    },
}

/// Converts released checkpoint state into the current layout.
///
/// Two things change across this boundary, and only one of them is a layout
/// change:
///
/// - `pending_transition` is genuinely new, and can only take its boundary default of "no rotation
///   outstanding" — the released protocol had no representation for an enacted predicate rotation
///   awaiting activation, so none can be in flight. Inserting it mid-container is what advances the
///   section's codec version.
/// - the denomination's type narrows from the released unchecked amount to the current bounded one.
///   Same encoding, so it does not advance a codec version. Both the denomination and the aggregate
///   `denomination x count` must fit within the bounded Bitcoin supply.
///
/// Every other field carries across by value.
pub fn migrate_from_v0(
    old: &CheckpointStateV0,
) -> Result<CheckpointState, CheckpointMigrationError> {
    let sats = old.deposits.denomination.to_sat();
    let denomination = BitcoinAmount::try_from(sats)
        .map_err(|_| CheckpointMigrationError::DenominationOutsideMoneySupply { sats })?;
    let count = old.deposits.count;
    let total_sats = u128::from(sats) * u128::from(count);
    let total_error = || CheckpointMigrationError::DepositPoolTotalOutsideMoneySupply {
        denomination_sats: sats,
        count,
        total_sats,
    };
    let total_sats_u64 = u64::try_from(total_sats).map_err(|_| total_error())?;
    BitcoinAmount::try_from(total_sats_u64)
        .map(|_| ())
        .map_err(|_| total_error())?;

    Ok(CheckpointState {
        sequencer_predicate: old.sequencer_predicate.clone(),
        checkpoint_predicate: old.checkpoint_predicate.clone(),
        // No rotation can be outstanding across the boundary: the released
        // protocol could not represent one.
        pending_transition: Default::default(),
        verified_tip: old.verified_tip,
        deposits: DepositPool {
            denomination,
            count,
        },
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
    use ssz::Encode;
    use strata_asm_checkpoint_types::CheckpointTip;
    use strata_btc_types::BitcoinAmount;
    use strata_checkpoint_verification_v0::DepositPool as DepositPoolV0;
    use strata_identifiers::{Buf32, L2BlockCommitment};
    use strata_predicate::{PredicateKey, PredicateTypeId};

    use super::*;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    fn released_pool(denomination_sat: u64, count: u32) -> CheckpointStateV0 {
        CheckpointStateV0 {
            sequencer_predicate: predicate(0x11),
            checkpoint_predicate: predicate(0x22),
            verified_tip: CheckpointTip::new(
                3,
                200,
                L2BlockCommitment::new(1, Buf32::zero().into()),
            ),
            deposits: DepositPoolV0 {
                denomination: BitcoinAmount::from(Amount::from_sat(denomination_sat)),
                count,
            },
        }
    }

    fn released(denomination_sat: u64) -> CheckpointStateV0 {
        released_pool(denomination_sat, 7)
    }

    #[test]
    fn carries_every_released_field_across() {
        let old = released(10_000_000);
        let new = migrate_from_v0(&old).expect("in-supply denomination converts");

        assert_eq!(new.sequencer_predicate(), &old.sequencer_predicate);
        assert_eq!(new.checkpoint_predicate(), &old.checkpoint_predicate);
        assert_eq!(new.verified_tip(), &old.verified_tip);
        assert_eq!(new.deposits.denomination.to_sat(), 10_000_000);
        assert_eq!(new.deposits.count, 7);
    }

    /// The only field with no released counterpart takes the sole value it
    /// could: the released protocol had no representation for an outstanding
    /// rotation, so none can cross the boundary.
    #[test]
    fn no_predicate_rotation_crosses_the_boundary() {
        let new = migrate_from_v0(&released(1)).expect("converts");
        assert!(new.pending_transition().is_none());
    }

    /// A denomination the released amount type accepted but the current one
    /// rejects is reported, not clamped.
    #[test]
    fn out_of_supply_denomination_is_reported() {
        assert_eq!(
            migrate_from_v0(&released(u64::MAX)),
            Err(CheckpointMigrationError::DenominationOutsideMoneySupply { sats: u64::MAX }),
        );
    }

    /// A released denomination can be valid while the pool it represents is
    /// not. Reject that state at migration so later calls to `total()` cannot
    /// panic and no state can claim more deposit value than Bitcoin can hold.
    #[test]
    fn out_of_supply_deposit_pool_total_is_reported() {
        const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;
        let total_sats = u128::from(MAX_MONEY_SATS) * 2;

        assert_eq!(
            migrate_from_v0(&released_pool(MAX_MONEY_SATS, 2)),
            Err(
                CheckpointMigrationError::DepositPoolTotalOutsideMoneySupply {
                    denomination_sats: MAX_MONEY_SATS,
                    count: 2,
                    total_sats,
                }
            ),
        );
    }

    /// The aggregate check is inclusive: a pool totaling the full Bitcoin
    /// supply is still representable and must migrate successfully.
    #[test]
    fn deposit_pool_total_at_money_supply_is_accepted() {
        const HALF_MAX_MONEY_SATS: u64 = 1_050_000_000_000_000;
        let new = migrate_from_v0(&released_pool(HALF_MAX_MONEY_SATS, 2))
            .expect("aggregate at the money-supply bound converts");

        assert_eq!(new.deposits.total().to_sat(), 2_100_000_000_000_000);
    }

    /// Why this section's codec version advances: inserting
    /// `pending_transition` mid-container adds an offset and shifts every field
    /// after it, so the two layouts do not share an encoding even when every
    /// carried value is equal.
    #[test]
    fn the_two_layouts_do_not_share_an_encoding() {
        let old = released(10_000_000);
        let new = migrate_from_v0(&old).expect("converts");

        assert_ne!(
            old.as_ssz_bytes(),
            new.as_ssz_bytes(),
            "an inserted variable-size field must change the encoding",
        );
    }
}
