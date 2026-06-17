use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_crypto::threshold_signature::ThresholdConfigUpdate;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the Strata administrator multisig configuration.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct StrataAdminMultisigUpdate(ThresholdConfigUpdate);

impl StrataAdminMultisigUpdate {
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

impl RenderSigningMessage for StrataAdminMultisigUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::StrataAdminMultisigUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        super::render::multisig(&self.0, details)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_crypto::keys::compressed::CompressedPublicKey;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn renders_signing_message() {
        let member = CompressedPublicKey::from_slice(&[2u8; 33]).expect("valid compressed key");
        let update = StrataAdminMultisigUpdate::new(
            ThresholdConfigUpdate::try_new(
                vec![member],
                vec![],
                NonZero::new(2).expect("non-zero"),
            )
            .expect("valid threshold config"),
        );
        let action = MultisigAction::Update(UpdateAction::StrataAdminMultisig(update));

        let message = SigningMessage::for_action(&action, 4);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: Strata Administrator Multisig Update\n\
             Authorized By: Strata Administrator\n\
             Sequence: 4\n\
             Action Details:\n  \
             New Threshold: 2\n  \
             Members to Add: 1\n  \
             1. Add Member: 020202020202020202020202020202020202020202020202020202020202020202\n  \
             Members to Remove: 0",
        );
    }
}
