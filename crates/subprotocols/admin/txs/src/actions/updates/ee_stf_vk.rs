use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_predicate::PredicateKey;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the verifying key for the EE STF.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct EeStfVkUpdate(PredicateKey);

impl EeStfVkUpdate {
    pub fn new(key: PredicateKey) -> Self {
        Self(key)
    }

    pub fn key(&self) -> &PredicateKey {
        &self.0
    }

    pub fn into_key(self) -> PredicateKey {
        self.0
    }
}

impl RenderSigningMessage for EeStfVkUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::EeStfVkUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        super::render::predicate(&self.0, details)
    }
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn renders_signing_message_small_predicate() {
        let key = PredicateKey::new(PredicateTypeId::Sp1Groth16, vec![0xca, 0xfe]);
        let update = EeStfVkUpdate::new(key);
        let action = MultisigAction::Update(UpdateAction::EeStfVk(update));

        let message = SigningMessage::for_action(&action, 11);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: EE STF VK Update\n\
             Authorized By: Alpen Administrator\n\
             Sequence: 11\n\
             Action Details:\n  \
             Predicate Type: Sp1Groth16\n  \
             Predicate Hex: cafe",
        );
    }
}
