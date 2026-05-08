use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_predicate::PredicateKey;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the verifying key for the ASM STF.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct AsmStfVkUpdate(PredicateKey);

impl AsmStfVkUpdate {
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

impl RenderSigningMessage for AsmStfVkUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::AsmStfVkUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        super::render::predicate(&self.0, details)
    }
}

#[cfg(test)]
mod tests {
    use strata_crypto::hash;
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn renders_signing_message_large_predicate_uses_hash() {
        let condition = vec![0x42; 64];
        let expected_hash = format!("{:x}", hash::raw(&condition));
        let key = PredicateKey::new(PredicateTypeId::Sp1Groth16, condition);
        let update = AsmStfVkUpdate::new(key);
        let action = MultisigAction::Update(UpdateAction::AsmStfVk(update));

        let message = SigningMessage::for_action(&action, 5);
        assert_eq!(
            message.as_str(),
            format!(
                "Strata ASM Administration v1\n\
                 Action: ASM STF VK Update\n\
                 Authorized By: Strata Administrator\n\
                 Sequence: 5\n\
                 Action Details:\n  \
                 Predicate Type: Sp1Groth16\n  \
                 Predicate Hash: {expected_hash}"
            ),
        );
    }
}
