use std::fmt;

use crate::Role;

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

impl UpdateTxType {
    pub fn authorized_role(&self) -> Role {
        match self {
            Self::StrataAdminMultisigUpdate => Role::StrataAdministrator,
            Self::OlStfVkUpdate => Role::StrataAdministrator,
            Self::AsmStfVkUpdate => Role::StrataAdministrator,
            Self::OperatorUpdate => Role::StrataAdministrator,

            Self::AlpenAdminMultisigUpdate => Role::AlpenAdministrator,
            Self::EeStfVkUpdate => Role::AlpenAdministrator,

            Self::SequencerUpdate => Role::StrataSequencerManager,
            Self::StrataSeqManagerMultisigUpdate => Role::StrataSequencerManager,
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
            Self::OperatorUpdate => "Bridge Operator Set Update",
            Self::SequencerUpdate => "Sequencer Update",
            Self::OlStfVkUpdate => "OL STF VK Update",
            Self::AsmStfVkUpdate => "ASM STF VK Update",
            Self::EeStfVkUpdate => "EE STF VK Update",
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
                Just(UpdateTxType::OperatorUpdate),
                Just(UpdateTxType::SequencerUpdate),
                Just(UpdateTxType::OlStfVkUpdate),
                Just(UpdateTxType::AsmStfVkUpdate),
                Just(UpdateTxType::EeStfVkUpdate),
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
    }
}
