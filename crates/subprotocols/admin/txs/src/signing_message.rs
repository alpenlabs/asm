use bitcoin::{hashes::Hash as _, sign_message::signed_msg_hash};
use strata_identifiers::Buf32;

use crate::actions::{IndentedDetails, MultisigAction, RenderSigningMessage};

/// Version of the admin subprotocol. The version is embedded in every signing message and
/// signed over, so bumping it on any breaking change to the subprotocol after deployment
/// ensures admin signatures cannot be reinterpreted under new subprotocol semantics.
pub const ADMIN_SUBPROTOCOL_VERSION: u8 = 1;

/// The canonical Bitcoin `signMessage` payload an admin signer signs over.
///
/// Constructed via [`SigningMessage::for_action`] from a [`MultisigAction`] and its sequence
/// number. The `Authorized By:` line is derived from the action via
/// [`MultisigAction::required_role`], so signers and verifiers cannot disagree on which role's
/// authority must validate the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningMessage(String);

impl SigningMessage {
    /// Renders the canonical signing-message payload for `action` at `seqno`.
    pub fn for_action(action: &MultisigAction, seqno: u64) -> Self {
        let mut lines = vec![
            format!("Strata ASM Administration v{ADMIN_SUBPROTOCOL_VERSION}"),
            format!("Action: {}", action.tx_type()),
            format!("Authorized By: {}", action.required_role()),
            format!("Sequence: {seqno}"),
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
    use strata_test_utils_arb::ArbitraryGenerator;

    use crate::{actions::MultisigAction, signing_message::SigningMessage};

    #[test]
    fn test_compute_hash_is_infalliable() {
        let mut arb = ArbitraryGenerator::new();
        let action: MultisigAction = arb.generate();
        let seqno: u64 = arb.generate();
        SigningMessage::for_action(&action, seqno).compute_sighash();
    }
}
