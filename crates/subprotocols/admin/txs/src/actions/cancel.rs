use arbitrary::Arbitrary;
use strata_asm_admin_types::AdminTxType;

use super::{IndentedDetails, RenderSigningMessage, UpdateAction};
use crate::actions::UpdateId;

/// A cancel of a queued update.
///
/// Only `target_id` goes on chain. The handler rebuilds the rest from the update queued under
/// that id, so a wrong id yields a different signing message and the signatures fail.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary)]
pub struct CancelAction {
    /// ID of the queued update to cancel.
    ///
    /// Not part of the signing message. Update IDs come from a global counter, so a signer
    /// cannot check one without looking up the live queue.
    target_id: UpdateId,
    /// The update queued under `target_id`. The signing message shows it, and its role is
    /// the one that must authorize the cancel.
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
        details.push(format!("Target Update: {}", self.update.update_tx_type()));
        self.update.render_details(details);
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use strata_crypto::EvenPublicKey;
    use strata_identifiers::Buf32;

    use crate::{
        actions::{
            CancelAction, MultisigAction, UpdateAction, updates::strata_sequencer::SequencerUpdate,
        },
        signing_message::SigningMessage,
    };

    #[test]
    fn test_cancel_message_renders_target_update() {
        let key = EvenPublicKey::try_from(Buf32::from([7u8; 32])).expect("valid x-only key");
        let update = UpdateAction::Sequencer(SequencerUpdate::new(key));
        let action = MultisigAction::Cancel(CancelAction::new(7, update));

        let message = SigningMessage::for_action(&action, 9, Network::Regtest);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Network: regtest\n\
             Action: Cancel\n\
             Authorized By: Strata Sequencer Manager\n\
             Sequence: 9\n\
             Action Details:\n  \
             Target Update: Sequencer Update\n  \
             New Sequencer Key: 0707070707070707070707070707070707070707070707070707070707070707"
        );
    }
}
