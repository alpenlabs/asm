use bitcoin::{hashes::Hash as _, sign_message::signed_msg_hash};
use strata_asm_params::Role;
use strata_identifiers::Buf32;

use crate::actions::{MultisigAction, SigningMessage};

const SIGNING_MESSAGE_VERSION: u8 = 1;

pub(crate) fn role_label(role: Role) -> &'static str {
    match role {
        Role::StrataAdministrator => "StrataAdministrator",
        Role::StrataSequencerManager => "StrataSequencerManager",
        Role::AlpenAdministrator => "AlpenAdministrator",
    }
}

pub(crate) fn append_indexed_fields(
    lines: &mut Vec<String>,
    prefix: &str,
    values: impl IntoIterator<Item = String>,
) {
    let values: Vec<String> = values.into_iter().collect();
    lines.push(format!("{prefix}_count: {}", values.len()));
    for (idx, value) in values.into_iter().enumerate() {
        lines.push(format!("{prefix}_{}: {value}", idx + 1));
    }
}

/// Renders the canonical Bitcoin `signMessage` payload for admin signatures.
pub fn render_signing_message(action: &MultisigAction, seqno: u64, role: Role) -> String {
    let mut lines = vec![
        "Alpen Admin Action".to_string(),
        format!("version: {SIGNING_MESSAGE_VERSION}"),
        format!("role: {}", role_label(role)),
        format!("sequence: {seqno}"),
        format!("action_type: {}", action.tx_type()),
    ];
    action.render_details(&mut lines);
    lines.join("\n")
}

/// Computes the Bitcoin `signMessage` digest for an admin action.
pub fn compute_signing_message_hash(action: &MultisigAction, seqno: u64, role: Role) -> Buf32 {
    Buf32::from(signed_msg_hash(&render_signing_message(action, seqno, role)).to_byte_array())
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_crypto::{
        keys::compressed::CompressedPublicKey, threshold_signature::ThresholdConfigUpdate,
    };
    use strata_predicate::{PredicateKey, PredicateTypeId};

    use super::*;
    use crate::actions::{
        CancelAction, MultisigAction, UpdateAction, updates::seq::SequencerUpdate,
    };

    #[test]
    fn test_render_signing_message_is_stable() {
        let action = MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(
            Buf32::from([7u8; 32]),
        )));

        let message = render_signing_message(&action, 42, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\nversion: 1\nrole: StrataSequencerManager\nsequence: 42\naction_type: SequencerUpdate\nnew_sequencer_key: 0707070707070707070707070707070707070707070707070707070707070707"
        );
    }

    #[test]
    fn test_cancel_message_uses_resolved_role() {
        let action = MultisigAction::Cancel(CancelAction::new(7));

        let message = render_signing_message(&action, 9, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\nversion: 1\nrole: StrataSequencerManager\nsequence: 9\naction_type: Cancel\ntarget_id: 7"
        );
    }

    #[test]
    fn test_multisig_message_includes_decoded_fields() {
        let member = CompressedPublicKey::from_slice(&[2u8; 33]).expect("valid compressed key");
        let action = MultisigAction::Update(UpdateAction::StrataAdminMultisig(
            ThresholdConfigUpdate::new(vec![member], vec![], NonZero::new(2).expect("non-zero")),
        ));

        let message = render_signing_message(&action, 4, Role::StrataAdministrator);
        assert!(message.contains("target_role: StrataAdministrator"));
        assert!(message.contains("new_threshold: 2"));
        assert!(message.contains("add_member_count: 1"));
        assert!(message.contains(
            "add_member_1: 020202020202020202020202020202020202020202020202020202020202020202"
        ));
        assert!(message.contains("remove_member_count: 0"));
    }

    #[test]
    fn test_predicate_message_renders_small_condition_hex() {
        let action = MultisigAction::Update(UpdateAction::AsmStfVk(PredicateKey::new(
            PredicateTypeId::Sp1Groth16,
            vec![0xde, 0xad, 0xbe, 0xef],
        )));

        let message = render_signing_message(&action, 5, Role::StrataAdministrator);
        assert!(message.contains("proof_type: Asm"));
        assert!(message.contains("predicate_type: Sp1Groth16"));
        assert!(message.contains("condition_len: 4"));
        assert!(message.contains("condition_hex: deadbeef"));
    }
}
