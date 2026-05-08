use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_identifiers::Buf32;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the public key of the sequencer.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct SequencerUpdate {
    pub_key: Buf32,
}

impl SequencerUpdate {
    /// Create a new `SequencerUpdate` from the given public key.
    pub fn new(pub_key: Buf32) -> Self {
        Self { pub_key }
    }

    /// Borrow the new sequencer public key.
    pub fn pub_key(&self) -> &Buf32 {
        &self.pub_key
    }

    /// Consume and return the inner public key.
    pub fn into_inner(self) -> Buf32 {
        self.pub_key
    }
}

impl RenderSigningMessage for SequencerUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::SequencerUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        details.push(format!("New Sequencer Key: {:x}", self.pub_key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn sequencer_update_renders_signing_message() {
        let update = SequencerUpdate::new(Buf32::from([7u8; 32]));
        let action = MultisigAction::Update(UpdateAction::Sequencer(update));

        let message = SigningMessage::for_action(&action, 42);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: Sequencer Update\n\
             Authorized By: Strata Sequencer Manager\n\
             Sequence: 42\n\
             Action Details:\n  \
             New Sequencer Key: 0707070707070707070707070707070707070707070707070707070707070707",
        );
    }
}
