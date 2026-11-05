use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_admin_types::{AdminTxType, UpdateTxType};
use strata_crypto::EvenPublicKey;
use strata_identifiers::Buf32;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An update to the public key of the sequencer.
///
/// SSZ decoding rejects keys that are not BIP340 x-only points before the update can be
/// authorized or queued. The encoded key remains 32 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct SequencerUpdate {
    pub_key: EvenPublicKey,
}

impl SequencerUpdate {
    /// Create a new `SequencerUpdate` from the given public key.
    pub fn new(pub_key: EvenPublicKey) -> Self {
        Self { pub_key }
    }

    /// Borrow the new sequencer public key.
    pub fn pub_key(&self) -> &EvenPublicKey {
        &self.pub_key
    }

    /// Consume and return the inner public key.
    pub fn into_inner(self) -> EvenPublicKey {
        self.pub_key
    }
}

impl RenderSigningMessage for SequencerUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::SequencerUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        details.push(format!(
            "New Sequencer Key: {:x}",
            Buf32::from(self.pub_key)
        ));
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use ssz::{Decode, Encode};

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn sequencer_update_preserves_ssz_layout() {
        let bytes = [7u8; 32];
        let update = SequencerUpdate::from_ssz_bytes(&bytes).expect("valid x-only key");
        assert_eq!(update.as_ssz_bytes(), bytes);
        assert_eq!(Buf32::from(*update.pub_key()), Buf32::from(bytes));
    }

    #[test]
    fn sequencer_update_renders_signing_message() {
        let key = EvenPublicKey::try_from(Buf32::from([7u8; 32])).expect("valid x-only key");
        let update = SequencerUpdate::new(key);
        let action = MultisigAction::Update(UpdateAction::Sequencer(update));

        let message = SigningMessage::for_action(&action, 42, Network::Regtest);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Network: regtest\n\
             Action: Sequencer Update\n\
             Authorized By: Strata Sequencer Manager\n\
             Sequence: 42\n\
             Action Details:\n  \
             New Sequencer Key: 0707070707070707070707070707070707070707070707070707070707070707",
        );
    }
}
