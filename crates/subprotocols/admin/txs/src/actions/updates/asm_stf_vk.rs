use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_predicate::PredicateKey;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the verifying key for the ASM STF.
///
/// Every update carries the raw id of the fork the new proving artifact
/// implements. The id is opaque at this layer: future forks must be enactable
/// by artifacts that predate them, so the action cannot validate the id
/// against a known set. Consumers that know the mapping (the worker) activate
/// the fork. Each update is expected to name the fork it newly activates;
/// upholding that is on the multisig when authoring the action — the id
/// renders into the signing message, and signing one that names an
/// already-active fork is an operational flaw.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct AsmStfVkUpdate {
    /// The new verifying key for the ASM STF.
    key: PredicateKey,

    /// Raw id of the fork the new artifact implements.
    fork_id: u16,
}

impl AsmStfVkUpdate {
    pub fn new(key: PredicateKey, fork_id: u16) -> Self {
        Self { key, fork_id }
    }

    pub fn key(&self) -> &PredicateKey {
        &self.key
    }

    pub fn fork_id(&self) -> u16 {
        self.fork_id
    }

    pub fn into_parts(self) -> (PredicateKey, u16) {
        (self.key, self.fork_id)
    }
}

impl RenderSigningMessage for AsmStfVkUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::AsmStfVkUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        super::render::predicate(&self.key, details);
        details.push(format!("Fork Id: {}", self.fork_id));
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
        let update = AsmStfVkUpdate::new(key, 7);
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
                 Predicate Hash: {expected_hash}\n  \
                 Fork Id: 7"
            ),
        );
    }
}
