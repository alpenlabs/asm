use bitcoin::{hashes::Hash as _, sign_message::signed_msg_hash};
use strata_asm_params::Role;
use strata_identifiers::Buf32;

use crate::actions::{IndentedDetails, MultisigAction, SigningMessage};

const SIGNING_MESSAGE_VERSION: u8 = 2;

pub(crate) fn role_label(role: Role) -> &'static str {
    match role {
        Role::StrataAdministrator => "StrataAdministrator",
        Role::StrataSequencerManager => "StrataSequencerManager",
        Role::AlpenAdministrator => "AlpenAdministrator",
    }
}

pub(crate) fn append_indexed_fields(
    details: &mut IndentedDetails<'_>,
    prefix: &str,
    values: impl IntoIterator<Item = String>,
) {
    let values: Vec<String> = values.into_iter().collect();
    details.push(format!("{prefix} Count: {}", values.len()));
    for (idx, value) in values.into_iter().enumerate() {
        details.push(format!("{prefix} {}: {value}", idx + 1));
    }
}

/// Renders the canonical Bitcoin `signMessage` payload for admin signatures.
///
/// The `Role:` line is derived from `action` via [`MultisigAction::required_role`], so signers
/// and verifiers cannot disagree on which role's authority must validate the message.
pub fn render_signing_message(action: &MultisigAction, seqno: u64) -> String {
    let mut lines = vec![
        format!("Strata ASM Administration v{SIGNING_MESSAGE_VERSION}"),
        format!("Role: {}", role_label(action.required_role())),
        format!("Sequence: {seqno}"),
        format!("Action: {}", action.tx_type()),
        "Action Details:".to_string(),
    ];
    let mut details = IndentedDetails::new(&mut lines);
    action.render_details(&mut details);
    lines.join("\n")
}

/// Computes the Bitcoin `signMessage` digest for an admin action.
pub fn compute_signing_message_hash(action: &MultisigAction, seqno: u64) -> Buf32 {
    Buf32::from(signed_msg_hash(&render_signing_message(action, seqno)).to_byte_array())
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

        let message = render_signing_message(&action, 9);
        assert_eq!(
            message,
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
