use bitcoin::{hashes::Hash as _, sign_message::signed_msg_hash};
use strata_identifiers::Buf32;

use crate::actions::{IndentedDetails, MultisigAction, RenderSigningMessage, role_label};

/// Version of the canonical Bitcoin `signMessage` payload format. Bumped on any breaking change
/// to the rendered text so external signers (hardware wallets, signing services) can assert
/// they understand the format before signing.
pub const SIGNING_MESSAGE_VERSION: u8 = 2;

/// The canonical Bitcoin `signMessage` payload an admin signer signs over.
///
/// Constructed via [`SigningMessage::for_action`] from a [`MultisigAction`] and its sequence
/// number. The `Role:` line is derived from the action via [`MultisigAction::required_role`], so
/// signers and verifiers cannot disagree on which role's authority must validate the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningMessage(String);

impl SigningMessage {
    /// Renders the canonical signing-message payload for `action` at `seqno`.
    pub fn for_action(action: &MultisigAction, seqno: u64) -> Self {
        let mut lines = vec![
            format!("Strata ASM Administration v{SIGNING_MESSAGE_VERSION}"),
            format!("Role: {}", role_label(action.required_role())),
            format!("Sequence: {seqno}"),
            format!("Action: {}", action.tx_type()),
            "Action Details:".to_string(),
        ];
        let mut details = IndentedDetails::new(&mut lines);
        action.render_details(&mut details);
        Self(lines.join("\n"))
    }

    /// Borrow the rendered payload as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Computes the Bitcoin `signMessage` digest for this payload.
    pub fn compute_sighash(&self) -> Buf32 {
        Buf32::from(signed_msg_hash(&self.0).to_byte_array())
    }
}

#[cfg(test)]
mod tests {
    use strata_identifiers::Buf32;

    use super::*;
    use crate::actions::{CancelAction, UpdateAction, updates::strata_sequencer::SequencerUpdate};

    #[test]
    fn test_cancel_message_renders_embedded_update() {
        let update = UpdateAction::Sequencer(SequencerUpdate::new(Buf32::from([0x11u8; 32])));
        let action = MultisigAction::Cancel(CancelAction::new(7, update));

        let message = SigningMessage::for_action(&action, 9);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v2\n\
             Role: StrataSequencerManager\n\
             Sequence: 9\n\
             Action: Cancel\n\
             Action Details:\n  \
             Target Id: 7\n  \
             New Sequencer Key: 1111111111111111111111111111111111111111111111111111111111111111"
        );
    }
}
