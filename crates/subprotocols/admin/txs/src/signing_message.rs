use bitcoin::hashes::Hash as _;
use bitcoin::sign_message::signed_msg_hash;
use strata_asm_params::Role;
use strata_crypto::hash;
use strata_identifiers::Buf32;

use crate::actions::{MultisigAction, Sighash};

const SIGNING_MESSAGE_VERSION: u8 = 1;

fn role_label(role: Role) -> &'static str {
    match role {
        Role::StrataAdministrator => "StrataAdministrator",
        Role::StrataSequencerManager => "StrataSequencerManager",
    }
}

/// Returns the hash of the canonical action payload bytes shown to signers.
pub fn payload_hash(action: &MultisigAction) -> Buf32 {
    hash::raw(&action.sighash_payload())
}

/// Renders the canonical Bitcoin `signMessage` payload for admin signatures.
pub fn render_signing_message(action: &MultisigAction, seqno: u64, role: Role) -> String {
    format!(
        "Alpen Admin Action\nversion: {SIGNING_MESSAGE_VERSION}\nrole: {}\nsequence: {seqno}\naction_type: {}\npayload_hash: {}",
        role_label(role),
        action.tx_type(),
        hex::encode(payload_hash(action).0),
    )
}

/// Computes the Bitcoin `signMessage` digest for an admin action.
pub fn compute_signing_message_hash(action: &MultisigAction, seqno: u64, role: Role) -> Buf32 {
    Buf32::from(signed_msg_hash(&render_signing_message(action, seqno, role)).to_byte_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{CancelAction, updates::seq::SequencerUpdate, MultisigAction, UpdateAction};

    #[test]
    fn test_render_signing_message_is_stable() {
        let action = MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(
            Buf32::from([7u8; 32]),
        )));

        let message = render_signing_message(&action, 42, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\nversion: 1\nrole: StrataSequencerManager\nsequence: 42\naction_type: SequencerUpdate\npayload_hash: 4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
    }

    #[test]
    fn test_cancel_message_uses_resolved_role() {
        let action = MultisigAction::Cancel(CancelAction::new(7));

        let message = render_signing_message(&action, 9, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\nversion: 1\nrole: StrataSequencerManager\nsequence: 9\naction_type: Cancel\npayload_hash: 1561ade0621c5acf44b780521f95a1e0b19b4e5032945b860c4032fc28a3a23b"
        );
    }
}
