use arbitrary::{Arbitrary, Unstructured};
use ssz_derive::{Decode, Encode};
use strata_asm_admin_types::{AdminTxType, UpdateTxType};
use strata_crypto::EvenPublicKey;
use strata_identifiers::Buf32;

use super::ParseCheck;
use crate::{
    actions::{IndentedDetails, RenderSigningMessage},
    errors::AdministrationTxParseError,
};

/// An update to the public key of the sequencer.
///
/// The key is held as raw bytes, so any 32 bytes decode. That keeps every admin state that
/// already holds one of these (queued, or embedded in a cancel) decodable. The parser refuses an
/// update whose key fails [`parse_pub_key`](Self::parse_pub_key) before it is authorized or
/// queued; see [`parse_tx`](crate::parser::parse_tx).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
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

    /// Parses the new key as a BIP340 x-only public key.
    ///
    /// Returns `None` when the bytes are not the x-coordinate of a secp256k1 point. Checkpoint
    /// envelopes are authenticated by a tapscript `<key> OP_CHECKSIG` leaf, and no signature
    /// verifies against such a key, so enacting it would stop checkpoints from being accepted
    /// until another update replaced it.
    pub fn parse_pub_key(&self) -> Option<EvenPublicKey> {
        EvenPublicKey::try_from(self.pub_key).ok()
    }
}

// Generated updates carry a curve point, as the parser requires, so arbitrary admin txs
// round-trip through `parse_tx`.
impl<'a> Arbitrary<'a> for SequencerUpdate {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let key: EvenPublicKey = u.arbitrary()?;
        Ok(Self::new(key.into()))
    }
}

// A key that is not a curve point is refused only for new txs; queued and cancel-embedded copies
// still decode, so legacy state keeps loading.
impl ParseCheck for SequencerUpdate {
    fn check_on_parse(&self) -> Result<(), AdministrationTxParseError> {
        match self.parse_pub_key() {
            Some(_) => Ok(()),
            None => Err(AdministrationTxParseError::InvalidSequencerKey { key: self.pub_key }),
        }
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
    use bitcoin::Network;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn parse_pub_key_accepts_only_x_only_points() {
        let valid = Buf32::from([7u8; 32]);
        let parsed = SequencerUpdate::new(valid)
            .parse_pub_key()
            .expect("[7; 32] is the x-coordinate of a curve point");
        assert_eq!(Buf32::from(parsed), valid);

        // `[3; 32]` is below the field prime, but `x^3 + 7` has no square root there.
        // `[0xff; 32]` is above the field prime.
        for key in [[3u8; 32], [0xffu8; 32]] {
            assert_eq!(SequencerUpdate::new(Buf32::from(key)).parse_pub_key(), None);
        }
    }

    #[test]
    fn sequencer_update_renders_signing_message() {
        let update = SequencerUpdate::new(Buf32::from([7u8; 32]));
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
