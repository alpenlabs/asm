use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::AdminTxType;

use super::{IndentedDetails, RenderSigningMessage, UpdateAction};
use crate::actions::UpdateId;

#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct CancelAction {
    /// ID of the update that needs to be cancelled.
    target_id: UpdateId,
    /// The update being cancelled. Embedded so the signing message describes the full
    /// payload signers are authorizing the cancellation of, and so role resolution can
    /// proceed without consulting the queue.
    update: UpdateAction,
}

impl CancelAction {
    pub fn new(target_id: UpdateId, update: UpdateAction) -> Self {
        CancelAction { target_id, update }
    }

    pub fn target_id(&self) -> &UpdateId {
        &self.target_id
    }

    pub fn update(&self) -> &UpdateAction {
        &self.update
    }
}

impl RenderSigningMessage for CancelAction {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Cancel
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        details.push(format!("Target Id: {}", self.target_id));
        details.push(format!("Target Update: {}", self.update.update_tx_type()));
        self.update.render_details(details);
    }
}

#[cfg(test)]
mod tests {
    use strata_identifiers::Buf32;

    use crate::{
        actions::{
            CancelAction, MultisigAction, UpdateAction, updates::strata_sequencer::SequencerUpdate,
        },
        signing_message::SigningMessage,
    };

    #[test]
    fn test_cancel_message_renders_embedded_update() {
        let update = UpdateAction::Sequencer(SequencerUpdate::new(Buf32::from([0x11u8; 32])));
        let action = MultisigAction::Cancel(CancelAction::new(7, update));

        let message = SigningMessage::for_action(&action, 9);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: Cancel\n\
             Authorized By: Strata Sequencer Manager\n\
             Sequence: 9\n\
             Action Details:\n  \
             Target Id: 7\n  \
             Target Update: Sequencer Update\n  \
             New Sequencer Key: 1111111111111111111111111111111111111111111111111111111111111111"
        );
    }
}
