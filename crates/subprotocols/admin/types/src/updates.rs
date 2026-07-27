use std::fmt;

use crate::Role;

/// The set of update transaction types within the Administration subprotocol.
///
/// Discriminants are the on-the-wire SPS-50 byte values. Only uniqueness is
/// load-bearing, but by convention each authorizing role is assigned its own
/// decade so the byte alone tells you which multisig must sign:
///
/// - `10..=19` — [`Role::StrataAdministrator`]
/// - `20..=29` — [`Role::StrataSequencerManager`]
/// - `30..=39` — [`Role::AlpenAdministrator`]
/// - `40..=49` — [`Role::StrataSecurityCouncil`]
///
/// When adding a variant, place it in the band of the role that authorizes it
/// (see [`UpdateTxType::authorized_role`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UpdateTxType {
    /// Update the strata admin multisignature configuration.
    StrataAdminMultisigUpdate = 10,
    /// Update the verifying key for the OL STF.
    OlStfVkUpdate = 11,
    /// Update the verifying key for the ASM STF.
    AsmStfVkUpdate = 12,
    /// Update the set of authorized operators.
    OperatorUpdate = 13,
    /// Update the safe harbour destination address on the bridge.
    SafeHarbourAddressUpdate = 14,
    /// Update the strata security council multisignature configuration.
    StrataSecurityCouncilMultisigUpdate = 15,

    /// Update the strata seq manager multisignature configuration.
    StrataSeqManagerMultisigUpdate = 20,
    /// Update the sequencer configuration.
    SequencerUpdate = 21,

    /// Update the alpen admin multisignature configuration.
    AlpenAdminMultisigUpdate = 30,
    /// Update the verifying key for the EE STF.
    EeStfVkUpdate = 31,

    /// Authorize an immediate sweep of bridge funds to the Safe-Harbour.
    Defcon1 = 41,
    /// Authorize a sweep of bridge funds to the Safe-Harbour after timelock.
    Defcon3 = 43,
}

impl UpdateTxType {
    pub fn authorized_role(&self) -> Role {
        match self {
            Self::StrataAdminMultisigUpdate => Role::StrataAdministrator,
            Self::OlStfVkUpdate => Role::StrataAdministrator,
            Self::AsmStfVkUpdate => Role::StrataAdministrator,
            Self::OperatorUpdate => Role::StrataAdministrator,
            // The safe harbour destination is rotated by the administrator, not the
            // security council: the council can sweep funds to the safe harbour (via
            // Defcon signals) but must not also pick where they land, otherwise the
            // same authority could both trigger a sweep and steal the proceeds.
            Self::SafeHarbourAddressUpdate => Role::StrataAdministrator,
            // Security council membership is rotated by the administrator, not by the
            // council itself.
            Self::StrataSecurityCouncilMultisigUpdate => Role::StrataAdministrator,

            Self::AlpenAdminMultisigUpdate => Role::AlpenAdministrator,
            Self::EeStfVkUpdate => Role::AlpenAdministrator,

            Self::SequencerUpdate => Role::StrataSequencerManager,
            Self::StrataSeqManagerMultisigUpdate => Role::StrataSequencerManager,

            Self::Defcon1 | Self::Defcon3 => Role::StrataSecurityCouncil,
        }
    }

    /// Canonical name used in the signing-message payload.
    ///
    /// Must remain byte-stable: external signers (hardware wallets, signing services) hash
    /// the rendered payload, so changing these labels invalidates already-signed messages.
    pub fn name(&self) -> &'static str {
        match self {
            Self::StrataAdminMultisigUpdate => "Strata Administrator Multisig Update",
            Self::StrataSeqManagerMultisigUpdate => "Strata Sequencer Manager Multisig Update",
            Self::AlpenAdminMultisigUpdate => "Alpen Administrator Multisig Update",
            Self::StrataSecurityCouncilMultisigUpdate => "Strata Security Council Multisig Update",
            Self::OperatorUpdate => "Bridge Operator Set Update",
            Self::SequencerUpdate => "Sequencer Update",
            Self::OlStfVkUpdate => "OL STF VK Update",
            Self::AsmStfVkUpdate => "ASM STF VK Update",
            Self::EeStfVkUpdate => "EE STF VK Update",
            Self::Defcon1 => "Defcon 1",
            Self::Defcon3 => "Defcon 3",
            Self::SafeHarbourAddressUpdate => "Safe Harbour Address Update",
        }
    }
}

impl TryFrom<u8> for UpdateTxType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(UpdateTxType::StrataAdminMultisigUpdate),
            11 => Ok(UpdateTxType::OlStfVkUpdate),
            12 => Ok(UpdateTxType::AsmStfVkUpdate),
            13 => Ok(UpdateTxType::OperatorUpdate),
            14 => Ok(UpdateTxType::SafeHarbourAddressUpdate),
            15 => Ok(UpdateTxType::StrataSecurityCouncilMultisigUpdate),
            20 => Ok(UpdateTxType::StrataSeqManagerMultisigUpdate),
            21 => Ok(UpdateTxType::SequencerUpdate),
            30 => Ok(UpdateTxType::AlpenAdminMultisigUpdate),
            31 => Ok(UpdateTxType::EeStfVkUpdate),
            41 => Ok(UpdateTxType::Defcon1),
            43 => Ok(UpdateTxType::Defcon3),
            invalid => Err(invalid),
        }
    }
}

impl fmt::Display for UpdateTxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::UpdateTxType;

    impl Arbitrary for UpdateTxType {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(UpdateTxType::StrataAdminMultisigUpdate),
                Just(UpdateTxType::StrataSeqManagerMultisigUpdate),
                Just(UpdateTxType::AlpenAdminMultisigUpdate),
                Just(UpdateTxType::StrataSecurityCouncilMultisigUpdate),
                Just(UpdateTxType::OperatorUpdate),
                Just(UpdateTxType::SequencerUpdate),
                Just(UpdateTxType::OlStfVkUpdate),
                Just(UpdateTxType::AsmStfVkUpdate),
                Just(UpdateTxType::EeStfVkUpdate),
                Just(UpdateTxType::Defcon1),
                Just(UpdateTxType::Defcon3),
                Just(UpdateTxType::SafeHarbourAddressUpdate),
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
                UpdateTxType::try_from(*v).is_err()
            })
        ) {
            prop_assert!(UpdateTxType::try_from(value).is_err());
        }
    }
}
