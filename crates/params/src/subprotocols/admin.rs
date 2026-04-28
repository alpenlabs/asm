use std::{fmt, num::NonZero};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_crypto::threshold_signature::ThresholdConfig;

/// Initialization configuration for the administration subprotocol, containing [`ThresholdConfig`]
/// for each role.
///
/// Design choice: Uses individual named fields rather than `Vec<(Role, ThresholdConfig)>`
/// to ensure structural completeness - the compiler guarantees all config fields are
/// provided when constructing this struct. However, it does NOT prevent logical errors
/// like using the same config for multiple roles or mismatched role-field assignments.
/// The benefit is avoiding missing fields at compile-time rather than runtime validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct AdministrationInitConfig {
    /// ThresholdConfig for [StrataAdministrator](Role::StrataAdministrator).
    pub strata_administrator: ThresholdConfig,

    /// ThresholdConfig for [StrataSequencerManager](Role::StrataSequencerManager).
    pub strata_sequencer_manager: ThresholdConfig,

    /// ThresholdConfig for [AlpenAdministrator](Role::AlpenAdministrator).
    pub alpen_administrator: ThresholdConfig,

    /// The confirmation depth (CD) setting, in Bitcoin blocks: after an update transaction
    /// receives this many confirmations, the update is enacted automatically. During this
    /// confirmation period, the update can still be cancelled by submitting a cancel transaction.
    pub confirmation_depth: u16,

    /// Maximum allowed gap between consecutive sequence numbers for a given authority.
    ///
    /// A payload with `seqno > last_seqno + max_seqno_gap` is rejected. This prevents
    /// excessively large jumps in sequence numbers while still allowing non-sequential usage.
    #[ssz(with = "non_zero_u8")]
    pub max_seqno_gap: NonZero<u8>,
}

/// Roles with authority in the administration subprotocol.
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Encode, Decode,
)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(u8)]
#[ssz(enum_behaviour = "tag")]
pub enum Role {
    /// The multisig authority that has exclusive ability to:
    /// 1. update (add/remove) bridge signers
    /// 2. update (add/remove) bridge operators
    /// 3. update the definition of what is considered a valid bridge deposit address for:
    ///    - registering deposit UTXOs
    ///    - accepting and minting bridge deposits
    ///    - assigning registered UTXOs to withdrawal requests
    /// 4. update the verifying key for the OL STF
    StrataAdministrator,

    /// The multisig authority that has exclusive ability to change the canonical
    /// public key of the default orchestration layer sequencer.
    StrataSequencerManager,

    /// The multisig authority that has exclusive ability to update the `update_vk`
    /// (predicate key) of EE snark accounts, emitting an `EePredicateKeyUpdate`
    /// log that the OL STF applies during manifest processing.
    AlpenAdministrator,
}

/// Administration subprotocol transaction types.
///
/// This enum represents all valid transaction types for the Administration subprotocol.
/// Each variant corresponds to a specific transaction type with its associated u8 value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AdminTxType {
    /// Cancel a previously queued update.
    Cancel = 0,
    /// Update the strata admin multisignature configuration.
    StrataAdminMultisigUpdate = 10,
    /// Update the strata seq manager multisignature configuration.
    StrataSeqManagerMultisigUpdate = 11,
    /// Update the alpen admin multisignature configuration.
    AlpenAdminMultisigUpdate = 12,
    /// Update the set of authorized operators.
    OperatorUpdate = 20,
    /// Update the sequencer configuration.
    SequencerUpdate = 21,
    /// Update the verifying key for the OL STF.
    OlStfVkUpdate = 30,
    /// Update the verifying key for the ASM STF.
    AsmStfVkUpdate = 31,
    /// Update the verifying key for the EE STF.
    EeStfVkUpdate = 32,
}

impl From<AdminTxType> for u8 {
    fn from(tx_type: AdminTxType) -> Self {
        tx_type as u8
    }
}

impl TryFrom<u8> for AdminTxType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AdminTxType::Cancel),
            10 => Ok(AdminTxType::StrataAdminMultisigUpdate),
            11 => Ok(AdminTxType::StrataSeqManagerMultisigUpdate),
            12 => Ok(AdminTxType::AlpenAdminMultisigUpdate),
            20 => Ok(AdminTxType::OperatorUpdate),
            21 => Ok(AdminTxType::SequencerUpdate),
            30 => Ok(AdminTxType::OlStfVkUpdate),
            31 => Ok(AdminTxType::AsmStfVkUpdate),
            32 => Ok(AdminTxType::EeStfVkUpdate),
            invalid => Err(invalid),
        }
    }
}

impl fmt::Display for AdminTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminTxType::Cancel => write!(f, "Cancel"),
            AdminTxType::StrataAdminMultisigUpdate => write!(f, "StrataAdminMultisigUpdate"),
            AdminTxType::StrataSeqManagerMultisigUpdate => {
                write!(f, "StrataSeqManagerMultisigUpdate")
            }
            AdminTxType::AlpenAdminMultisigUpdate => write!(f, "AlpenAdminMultisigUpdate"),
            AdminTxType::OperatorUpdate => write!(f, "OperatorUpdate"),
            AdminTxType::SequencerUpdate => write!(f, "SequencerUpdate"),
            AdminTxType::OlStfVkUpdate => write!(f, "OlStfVkUpdate"),
            AdminTxType::AsmStfVkUpdate => write!(f, "AsmStfVkUpdate"),
            AdminTxType::EeStfVkUpdate => write!(f, "EeStfVkUpdate"),
        }
    }
}

impl AdministrationInitConfig {
    pub fn new(
        strata_administrator: ThresholdConfig,
        strata_sequencer_manager: ThresholdConfig,
        alpen_administrator: ThresholdConfig,
        confirmation_depth: u16,
        max_seqno_gap: NonZero<u8>,
    ) -> Self {
        Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            confirmation_depth,
            max_seqno_gap,
        }
    }

    pub fn get_config(&self, role: Role) -> &ThresholdConfig {
        match role {
            Role::StrataAdministrator => &self.strata_administrator,
            Role::StrataSequencerManager => &self.strata_sequencer_manager,
            Role::AlpenAdministrator => &self.alpen_administrator,
        }
    }

    pub fn get_all_authorities(self) -> Vec<(Role, ThresholdConfig)> {
        vec![
            (Role::StrataAdministrator, self.strata_administrator),
            (Role::StrataSequencerManager, self.strata_sequencer_manager),
            (Role::AlpenAdministrator, self.alpen_administrator),
        ]
    }
}

#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod non_zero_u8 {
    pub mod encode {
        use std::num::NonZero;

        use ssz::Encode as SszEncode;

        pub fn is_ssz_fixed_len() -> bool {
            <u8 as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <u8 as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &NonZero<u8>) -> usize {
            value.get().ssz_bytes_len()
        }

        pub fn ssz_append(value: &NonZero<u8>, buf: &mut Vec<u8>) {
            value.get().ssz_append(buf);
        }
    }

    pub mod decode {
        use std::num::NonZero;

        use ssz::{Decode as SszDecode, DecodeError};

        pub fn is_ssz_fixed_len() -> bool {
            <u8 as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <u8 as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<NonZero<u8>, DecodeError> {
            let value = u8::from_ssz_bytes(bytes)?;
            NonZero::new(value)
                .ok_or_else(|| DecodeError::BytesInvalid("max_seqno_gap must be non-zero".into()))
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AdministrationInitConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let strata_administrator = u.arbitrary()?;
        let strata_sequencer_manager = u.arbitrary()?;
        let alpen_administrator = u.arbitrary()?;
        let confirmation_depth = u.arbitrary()?;
        // Generate a valid NonZero<u8> by mapping [0, 255) to [1, 256) via saturating add.
        let raw: u8 = u.arbitrary()?;
        let max_seqno_gap = NonZero::new(raw.saturating_add(1))
            .expect("saturating_add(1) on u8 always produces a non-zero value");

        Ok(Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            confirmation_depth,
            max_seqno_gap,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::AdminTxType;

    impl Arbitrary for AdminTxType {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(AdminTxType::Cancel),
                Just(AdminTxType::StrataAdminMultisigUpdate),
                Just(AdminTxType::StrataSeqManagerMultisigUpdate),
                Just(AdminTxType::AlpenAdminMultisigUpdate),
                Just(AdminTxType::OperatorUpdate),
                Just(AdminTxType::SequencerUpdate),
                Just(AdminTxType::OlStfVkUpdate),
                Just(AdminTxType::AsmStfVkUpdate),
                Just(AdminTxType::EeStfVkUpdate),
            ]
            .boxed()
        }
    }

    proptest! {
        #[test]
        fn test_admin_tx_type_roundtrip(tx_type: AdminTxType) {
            let as_u8: u8 = tx_type.into();
            let back_to_enum = AdminTxType::try_from(as_u8)
                .expect("roundtrip conversion should succeed");
            prop_assert_eq!(tx_type, back_to_enum);
        }

        #[test]
        fn test_admin_tx_type_invalid_values(
            value in (0u8..=255u8).prop_filter("must not be a valid variant", |v| {
                !matches!(*v, 0 | 10 | 11 | 12 | 20 | 21 | 30 | 31 | 32)
            })
        ) {
            prop_assert!(AdminTxType::try_from(value).is_err());
        }
    }
}
