use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_predicate::PredicateKey;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the verifying key for the OL STF.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct OlStfVkUpdate(PredicateKey);

impl OlStfVkUpdate {
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

impl RenderSigningMessage for OlStfVkUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::OlStfVkUpdate)
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
        let key = PredicateKey::new(PredicateTypeId::Sp1Groth16, vec![0xde, 0xad, 0xbe, 0xef]);
        let update = OlStfVkUpdate::new(key);
        let action = MultisigAction::Update(UpdateAction::OlStfVk(update));

        let message = SigningMessage::for_action(&action, 3);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: OL STF VK Update\n\
             Authorized By: Strata Administrator\n\
             Sequence: 3\n\
             Action Details:\n  \
             Predicate Type: Sp1Groth16\n  \
             Predicate Hex: deadbeef",
        );
    }
}
