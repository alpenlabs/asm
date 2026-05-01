use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_predicate::PredicateKey;

use crate::actions::SigningMessage;

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

impl SigningMessage for AsmStfVkUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::AsmStfVkUpdate)
    }

    fn render_details(&self, lines: &mut Vec<String>) {
        super::render::predicate("Asm", &self.0, lines)
    }
}

#[cfg(test)]
mod tests {
    use strata_asm_params::Role;
    use strata_crypto::hash;
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::render_signing_message,
    };

    #[test]
    fn renders_signing_message_large_condition_uses_hash() {
        let condition = vec![0x42; 64];
        let expected_hash = format!("{:x}", hash::raw(&condition));
        let key = PredicateKey::new(PredicateTypeId::Sp1Groth16, condition);
        let update = AsmStfVkUpdate::new(key);
        let action = MultisigAction::Update(UpdateAction::AsmStfVk(update));

        let message = render_signing_message(&action, 5, Role::StrataAdministrator);
        assert_eq!(
            message,
            format!(
                "Alpen Admin Action\n\
                 version: 1\n\
                 role: StrataAdministrator\n\
                 sequence: 5\n\
                 action_type: AsmStfVkUpdate\n\
                 proof_type: Asm\n\
                 predicate_type: Sp1Groth16\n\
                 condition_len: 64\n\
                 condition_hash: {expected_hash}"
            ),
        );
    }
}
