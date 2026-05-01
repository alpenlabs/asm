use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_predicate::PredicateKey;

use crate::actions::SigningMessage;

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

impl SigningMessage for EeStfVkUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::EeStfVkUpdate)
    }

    fn render_details(&self, lines: &mut Vec<String>) {
        super::render::predicate("EeStf", &self.0, lines)
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_params::Role;
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::render_signing_message,
    };

    #[test]
    fn renders_signing_message_small_condition() {
        let key = PredicateKey::new(PredicateTypeId::Sp1Groth16, vec![0xca, 0xfe]);
        let update = EeStfVkUpdate::new(key);
        let action = MultisigAction::Update(UpdateAction::EeStfVk(update));

        let message = render_signing_message(&action, 11, Role::AlpenAdministrator);
        assert_eq!(
            message,
            "Alpen Admin Action\n\
             version: 1\n\
             role: AlpenAdministrator\n\
             sequence: 11\n\
             action_type: EeStfVkUpdate\n\
             proof_type: EeStf\n\
             predicate_type: Sp1Groth16\n\
             condition_len: 2\n\
             condition_hex: cafe",
        );
    }
}
