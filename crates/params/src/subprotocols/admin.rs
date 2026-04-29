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

    /// Per-variant confirmation depths (CD) for queued admin updates.
    pub confirmation_depths: ConfirmationDepths,

    /// Maximum allowed gap between consecutive sequence numbers for a given authority.
    ///
    /// A payload with `seqno > last_seqno + max_seqno_gap` is rejected. This prevents
    /// excessively large jumps in sequence numbers while still allowing non-sequential usage.
    #[ssz(with = "non_zero_u8")]
    pub max_seqno_gap: NonZero<u8>,
}

/// Per-variant confirmation depths (CD) for admin updates, in Bitcoin blocks.
///
/// After an update transaction receives this many confirmations, the update is enacted
/// automatically. During this confirmation period, the update can still be cancelled by
/// submitting a cancel transaction. A field value of `0` is a sentinel for "apply
/// immediately" — such updates bypass the queue entirely and surface from [`Self::get`]
/// as `None`.
///
/// Design choice: individual named fields rather than a `HashMap<UpdateTxType, u16>` give
/// compile-time completeness — adding a new [`UpdateTxType`] variant forces a matching
/// field here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ConfirmationDepths {
    pub strata_admin_multisig_update: u16,
    pub strata_seq_manager_multisig_update: u16,
    pub alpen_admin_multisig_update: u16,
    pub operator_update: u16,
    pub sequencer_update: u16,
    pub ol_stf_vk_update: u16,
    pub asm_stf_vk_update: u16,
    pub ee_stf_vk_update: u16,
}

impl ConfirmationDepths {
    /// Returns the confirmation depth configured for `tx_type`, or `None` if the update
    /// is configured to bypass the queue and apply immediately (depth `0`).
    pub fn get(&self, tx_type: UpdateTxType) -> Option<u16> {
        let depth = match tx_type {
            UpdateTxType::StrataAdminMultisigUpdate => self.strata_admin_multisig_update,
            UpdateTxType::StrataSeqManagerMultisigUpdate => self.strata_seq_manager_multisig_update,
            UpdateTxType::AlpenAdminMultisigUpdate => self.alpen_admin_multisig_update,
            UpdateTxType::OperatorUpdate => self.operator_update,
            UpdateTxType::SequencerUpdate => self.sequencer_update,
            UpdateTxType::OlStfVkUpdate => self.ol_stf_vk_update,
            UpdateTxType::AsmStfVkUpdate => self.asm_stf_vk_update,
            UpdateTxType::EeStfVkUpdate => self.ee_stf_vk_update,
        };
        (depth != 0).then_some(depth)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ConfirmationDepths {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            strata_admin_multisig_update: u.arbitrary()?,
            strata_seq_manager_multisig_update: u.arbitrary()?,
            alpen_admin_multisig_update: u.arbitrary()?,
            operator_update: u.arbitrary()?,
            sequencer_update: u.arbitrary()?,
            ol_stf_vk_update: u.arbitrary()?,
            asm_stf_vk_update: u.arbitrary()?,
            ee_stf_vk_update: u.arbitrary()?,
        })
    }
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
/// by [`UpdateTxType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminTxType {
    /// Cancel a previously queued update.
    Cancel,
    /// Propose an update of the kind described by [`UpdateTxType`].
    Update(UpdateTxType),
}

/// The set of update transaction types within the Administration subprotocol.
///
/// Discriminants are the on-the-wire SPS-50 byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UpdateTxType {
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

/// On-the-wire SPS-50 byte value for [`AdminTxType::Cancel`].
const CANCEL_TX_TYPE: u8 = 0;

impl From<UpdateTxType> for u8 {
    fn from(tx_type: UpdateTxType) -> Self {
        tx_type as u8
    }
}

impl From<UpdateTxType> for AdminTxType {
    fn from(tx_type: UpdateTxType) -> Self {
        AdminTxType::Update(tx_type)
    }
}

impl TryFrom<AdminTxType> for UpdateTxType {
    type Error = AdminTxType;

    fn try_from(tx_type: AdminTxType) -> Result<Self, Self::Error> {
        match tx_type {
            AdminTxType::Update(u) => Ok(u),
            AdminTxType::Cancel => Err(tx_type),
        }
    }
}

impl From<AdminTxType> for u8 {
    fn from(tx_type: AdminTxType) -> Self {
        match tx_type {
            AdminTxType::Cancel => CANCEL_TX_TYPE,
            AdminTxType::Update(u) => u.into(),
        }
    }
}

impl TryFrom<u8> for UpdateTxType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(UpdateTxType::StrataAdminMultisigUpdate),
            11 => Ok(UpdateTxType::StrataSeqManagerMultisigUpdate),
            12 => Ok(UpdateTxType::AlpenAdminMultisigUpdate),
            20 => Ok(UpdateTxType::OperatorUpdate),
            21 => Ok(UpdateTxType::SequencerUpdate),
            30 => Ok(UpdateTxType::OlStfVkUpdate),
            31 => Ok(UpdateTxType::AsmStfVkUpdate),
            32 => Ok(UpdateTxType::EeStfVkUpdate),
            invalid => Err(invalid),
        }
    }
}

impl TryFrom<u8> for AdminTxType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            CANCEL_TX_TYPE => Ok(AdminTxType::Cancel),
            other => UpdateTxType::try_from(other).map(AdminTxType::Update),
        }
    }
}

impl fmt::Display for UpdateTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateTxType::StrataAdminMultisigUpdate => write!(f, "StrataAdminMultisigUpdate"),
            UpdateTxType::StrataSeqManagerMultisigUpdate => {
                write!(f, "StrataSeqManagerMultisigUpdate")
            }
            UpdateTxType::AlpenAdminMultisigUpdate => write!(f, "AlpenAdminMultisigUpdate"),
            UpdateTxType::OperatorUpdate => write!(f, "OperatorUpdate"),
            UpdateTxType::SequencerUpdate => write!(f, "SequencerUpdate"),
            UpdateTxType::OlStfVkUpdate => write!(f, "OlStfVkUpdate"),
            UpdateTxType::AsmStfVkUpdate => write!(f, "AsmStfVkUpdate"),
            UpdateTxType::EeStfVkUpdate => write!(f, "EeStfVkUpdate"),
        }
    }
}

impl fmt::Display for AdminTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminTxType::Cancel => write!(f, "Cancel"),
            AdminTxType::Update(u) => u.fmt(f),
        }
    }
}

impl AdministrationInitConfig {
    pub fn new(
        strata_administrator: ThresholdConfig,
        strata_sequencer_manager: ThresholdConfig,
        alpen_administrator: ThresholdConfig,
        confirmation_depths: ConfirmationDepths,
        max_seqno_gap: NonZero<u8>,
    ) -> Self {
        Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            confirmation_depths,
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
        let confirmation_depths = u.arbitrary()?;
        // Generate a valid NonZero<u8> by mapping [0, 255) to [1, 256) via saturating add.
        let raw: u8 = u.arbitrary()?;
        let max_seqno_gap = NonZero::new(raw.saturating_add(1))
            .expect("saturating_add(1) on u8 always produces a non-zero value");

        Ok(Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            confirmation_depths,
            max_seqno_gap,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{AdminTxType, UpdateTxType};

    impl Arbitrary for UpdateTxType {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(UpdateTxType::StrataAdminMultisigUpdate),
                Just(UpdateTxType::StrataSeqManagerMultisigUpdate),
                Just(UpdateTxType::AlpenAdminMultisigUpdate),
                Just(UpdateTxType::OperatorUpdate),
                Just(UpdateTxType::SequencerUpdate),
                Just(UpdateTxType::OlStfVkUpdate),
                Just(UpdateTxType::AsmStfVkUpdate),
                Just(UpdateTxType::EeStfVkUpdate),
            ]
            .boxed()
        }
    }

    impl Arbitrary for AdminTxType {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(AdminTxType::Cancel),
                any::<UpdateTxType>().prop_map(AdminTxType::Update),
            ]
            .boxed()
        }
    }

    proptest! {
        #[test]
        fn test_update_tx_type_roundtrip(tx_type: UpdateTxType) {
            let as_u8: u8 = tx_type.into();
            let back_to_enum = UpdateTxType::try_from(as_u8)
                .expect("roundtrip conversion should succeed");
            prop_assert_eq!(tx_type, back_to_enum);
        }

        #[test]
        fn test_update_tx_type_invalid_values(
            value in (0u8..=255u8).prop_filter("must not be a valid variant", |v| {
                !matches!(*v, 10 | 11 | 12 | 20 | 21 | 30 | 31 | 32)
            })
        ) {
            prop_assert!(UpdateTxType::try_from(value).is_err());
        }

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
