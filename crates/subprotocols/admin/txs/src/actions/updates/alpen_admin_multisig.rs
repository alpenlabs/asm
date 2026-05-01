use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, Role, UpdateTxType};
use strata_crypto::threshold_signature::ThresholdConfigUpdate;

use crate::actions::SigningMessage;

/// An update to the Alpen administrator multisig configuration.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct AlpenAdminMultisigUpdate(ThresholdConfigUpdate);

impl AlpenAdminMultisigUpdate {
    pub fn new(config: ThresholdConfigUpdate) -> Self {
        Self(config)
    }

    pub fn config(&self) -> &ThresholdConfigUpdate {
        &self.0
    }

    pub fn into_config(self) -> ThresholdConfigUpdate {
        self.0
    }
}

impl SigningMessage for AlpenAdminMultisigUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::AlpenAdminMultisigUpdate)
    }

    fn render_details(&self, lines: &mut Vec<String>) {
        super::render::multisig(Role::AlpenAdministrator, &self.0, lines)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_crypto::keys::compressed::CompressedPublicKey;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::render_signing_message,
    };

    #[test]
    fn renders_signing_message() {
        let member = CompressedPublicKey::from_slice(&[2u8; 33]).expect("valid compressed key");
        let update = AlpenAdminMultisigUpdate::new(ThresholdConfigUpdate::new(
            vec![member],
            vec![],
            NonZero::new(2).expect("non-zero"),
        ));
        let action = MultisigAction::Update(UpdateAction::AlpenAdminMultisig(update));

        let message = render_signing_message(&action, 12, Role::AlpenAdministrator);
        assert_eq!(
            message,
            "Alpen Admin Action\n\
             version: 1\n\
             role: AlpenAdministrator\n\
             sequence: 12\n\
             action_type: AlpenAdminMultisigUpdate\n\
             target_role: AlpenAdministrator\n\
             new_threshold: 2\n\
             add_member_count: 1\n\
             add_member_1: 020202020202020202020202020202020202020202020202020202020202020202\n\
             remove_member_count: 0",
        );
    }
}
