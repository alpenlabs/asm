use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, Role, UpdateTxType};
use strata_crypto::threshold_signature::ThresholdConfigUpdate;

use crate::actions::SigningMessage;

/// An update to the Strata sequencer-manager multisig configuration.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct StrataSeqManagerMultisigUpdate(ThresholdConfigUpdate);

impl StrataSeqManagerMultisigUpdate {
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

impl SigningMessage for StrataSeqManagerMultisigUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::StrataSeqManagerMultisigUpdate)
    }

    fn render_details(&self, lines: &mut Vec<String>) {
        super::render::multisig(Role::StrataSequencerManager, &self.0, lines)
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
    fn strata_seq_manager_multisig_update_renders_signing_message() {
        let member = CompressedPublicKey::from_slice(&[2u8; 33]).expect("valid compressed key");
        let update = StrataSeqManagerMultisigUpdate::new(ThresholdConfigUpdate::new(
            vec![member],
            vec![],
            NonZero::new(2).expect("non-zero"),
        ));
        let action = MultisigAction::Update(UpdateAction::StrataSeqManagerMultisig(update));

        let message = render_signing_message(&action, 7, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\n\
             version: 1\n\
             role: StrataSequencerManager\n\
             sequence: 7\n\
             action_type: StrataSeqManagerMultisigUpdate\n\
             target_role: StrataSequencerManager\n\
             new_threshold: 2\n\
             add_member_count: 1\n\
             add_member_1: 020202020202020202020202020202020202020202020202020202020202020202\n\
             remove_member_count: 0",
        );
    }
}
