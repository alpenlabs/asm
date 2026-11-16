use bitcoin::{
    Network,
    hashes::Hash as _,
    secp256k1::{Message, SECP256K1, SecretKey},
    sign_message::{MessageSignature, signed_msg_hash},
};
use strata_identifiers::Buf32;

use crate::actions::{IndentedDetails, MultisigAction, RenderSigningMessage};

/// Version of the admin subprotocol. The version is embedded in every signing message and
/// signed over, so bumping it on any breaking change to the subprotocol after deployment
/// ensures admin signatures cannot be reinterpreted under new subprotocol semantics.
pub const ADMIN_SUBPROTOCOL_VERSION: u8 = 1;

/// The canonical Bitcoin `signMessage` payload an admin signer signs over.
///
/// Constructed via [`SigningMessage::for_action`] from a [`MultisigAction`], its sequence
/// number and the network the chain is anchored to. The `Authorized By:` line is derived
/// from the action via [`MultisigAction::required_role`], so signers and verifiers cannot
/// disagree on which role's authority must validate the message.
///
/// The network gets its own line rather than only shaping the address prefixes further down,
/// so that an action carrying no Bitcoin address is still bound to one chain. Without it the
/// same payload would hash identically on mainnet and on regtest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningMessage(String);

impl SigningMessage {
    /// Renders the canonical signing-message payload for `action` at `seqno`, showing any
    /// Bitcoin address it carries on `network`.
    pub fn for_action(action: &MultisigAction, seqno: u64, network: Network) -> Self {
        let mut lines = vec![
            format!("Strata ASM Administration v{ADMIN_SUBPROTOCOL_VERSION}"),
            format!("Network: {network}"),
            format!("Action: {}", action.tx_type()),
            format!("Authorized By: {}", action.required_role()),
            format!("Sequence: {seqno}"),
        ];
        let mut detail_lines = Vec::new();
        let mut details = IndentedDetails::new(&mut detail_lines, network);
        action.render_details(&mut details);
        if !detail_lines.is_empty() {
            lines.push("Action Details:".to_string());
            lines.extend(detail_lines);
        }
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

    /// Signs this payload as Bitcoin Core's `signmessage` does, returning the 65-byte
    /// BIP-137 signature (`header || r || s`) with a compressed-key header.
    pub fn sign(&self, secret_key: &SecretKey) -> [u8; 65] {
        sign_bip137_digest(&self.compute_sighash().0, secret_key)
    }
}

/// Signs a `signMessage` digest and serializes it with a compressed-key BIP-137 header.
pub(crate) fn sign_bip137_digest(digest: &[u8; 32], secret_key: &SecretKey) -> [u8; 65] {
    let message = Message::from_digest(*digest);
    let signature = SECP256K1.sign_ecdsa_recoverable(&message, secret_key);
    MessageSignature::new(signature, true).serialize()
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::{
        Network,
        secp256k1::{PublicKey, SECP256K1, SecretKey},
    };
    use strata_asm_admin_threshold_sig::{
        IndexedSignature, P2wpkhAddress, ThresholdConfig, verify_threshold_signatures,
    };
    use strata_test_utils_arb::ArbitraryGenerator;

    use crate::{actions::MultisigAction, signing_message::SigningMessage};

    #[test]
    fn test_compute_hash_is_infalliable() {
        let mut arb = ArbitraryGenerator::new();
        let action: MultisigAction = arb.generate();
        let seqno: u64 = arb.generate();
        SigningMessage::for_action(&action, seqno, Network::Regtest).compute_sighash();
    }

    #[test]
    fn signature_passes_the_threshold_check() {
        let mut arb = ArbitraryGenerator::new();
        let action: MultisigAction = arb.generate();
        let message = SigningMessage::for_action(&action, 1, Network::Signet);
        let key = SecretKey::from_slice(&[7; 32]).expect("valid key");
        let signer = P2wpkhAddress::from_pubkey(&PublicKey::from_secret_key(SECP256K1, &key));
        let config = ThresholdConfig::try_new(vec![signer], NonZero::<u8>::MIN).expect("1-of-1");

        let signature = IndexedSignature::new(0, message.sign(&key));

        assert_eq!(
            verify_threshold_signatures(&config, &[signature], &message.compute_sighash().0),
            Ok(())
        );
    }
}
