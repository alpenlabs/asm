use bitcoin::{hashes::Hash as _, sign_message::signed_msg_hash};
use strata_asm_params::Role;
use strata_crypto::hash;
use strata_identifiers::Buf32;
use strata_predicate::PredicateTypeId;

use crate::actions::{
    CancelAction, MultisigAction, Sighash, UpdateAction,
    updates::{
        multisig::MultisigUpdate,
        operator::OperatorSetUpdate,
        predicate::{PredicateUpdate, ProofType},
        seq::SequencerUpdate,
    },
};

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

fn proof_type_label(proof_type: ProofType) -> &'static str {
    match proof_type {
        ProofType::Asm => "Asm",
        ProofType::OLStf => "OLStf",
    }
}

fn append_indexed_fields(
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

fn render_cancel_details(cancel: &CancelAction, lines: &mut Vec<String>) {
    lines.push(format!("target_id: {}", cancel.target_id()));
}

fn render_multisig_update_details(update: &MultisigUpdate, lines: &mut Vec<String>) {
    let config = update.config();
    lines.push(format!("target_role: {}", role_label(update.role())));
    lines.push(format!("new_threshold: {}", config.new_threshold()));
    append_indexed_fields(
        lines,
        "add_member",
        config
            .add_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
    append_indexed_fields(
        lines,
        "remove_member",
        config
            .remove_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
}

fn render_operator_update_details(update: &OperatorSetUpdate, lines: &mut Vec<String>) {
    append_indexed_fields(
        lines,
        "add_member",
        update
            .add_members()
            .iter()
            .cloned()
            .map(|member| format!("{:x}", Buf32::from(member))),
    );
    append_indexed_fields(
        lines,
        "remove_member",
        update.remove_members().iter().map(u32::to_string),
    );
}

fn render_sequencer_update_details(update: &SequencerUpdate, lines: &mut Vec<String>) {
    lines.push(format!("new_sequencer_key: {:x}", update.pub_key()));
}

fn render_predicate_update_details(update: &PredicateUpdate, lines: &mut Vec<String>) {
    let predicate_type = PredicateTypeId::try_from(update.key().id())
        .expect("predicate type should be validated at construction");
    let condition = update.key().condition();
    lines.push(format!("proof_type: {}", proof_type_label(update.kind())));
    lines.push(format!("predicate_type: {predicate_type}"));
    lines.push(format!("condition_len: {}", condition.len()));
    if condition.len() <= 32 {
        lines.push(format!("condition_hex: {}", hex::encode(condition)));
    } else {
        lines.push(format!("condition_hash: {:x}", hash::raw(condition)));
    }
}

fn render_action_details(action: &MultisigAction, lines: &mut Vec<String>) {
    match action {
        MultisigAction::Cancel(cancel) => render_cancel_details(cancel, lines),
        MultisigAction::Update(update) => match update {
            UpdateAction::Multisig(update) => render_multisig_update_details(update, lines),
            UpdateAction::OperatorSet(update) => render_operator_update_details(update, lines),
            UpdateAction::Sequencer(update) => render_sequencer_update_details(update, lines),
            UpdateAction::VerifyingKey(update) => render_predicate_update_details(update, lines),
        },
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
    render_action_details(action, &mut lines);
    lines.push(format!("payload_hash: {:x}", payload_hash(action)));
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
        CancelAction, MultisigAction, UpdateAction,
        updates::{
            multisig::MultisigUpdate,
            predicate::{PredicateUpdate, ProofType},
            seq::SequencerUpdate,
        },
    };

    #[test]
    fn test_render_signing_message_is_stable() {
        let action = MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(
            Buf32::from([7u8; 32]),
        )));

        let message = render_signing_message(&action, 42, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\nversion: 1\nrole: StrataSequencerManager\nsequence: 42\naction_type: SequencerUpdate\nnew_sequencer_key: 0707070707070707070707070707070707070707070707070707070707070707\npayload_hash: 4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
    }

    #[test]
    fn test_cancel_message_uses_resolved_role() {
        let action = MultisigAction::Cancel(CancelAction::new(7));

        let message = render_signing_message(&action, 9, Role::StrataSequencerManager);
        assert_eq!(
            message,
            "Alpen Admin Action\nversion: 1\nrole: StrataSequencerManager\nsequence: 9\naction_type: Cancel\ntarget_id: 7\npayload_hash: 1561ade0621c5acf44b780521f95a1e0b19b4e5032945b860c4032fc28a3a23b"
        );
    }

    #[test]
    fn test_multisig_message_includes_decoded_fields() {
        let member = CompressedPublicKey::from_slice(&[2u8; 33]).expect("valid compressed key");
        let action = MultisigAction::Update(UpdateAction::Multisig(MultisigUpdate::new(
            ThresholdConfigUpdate::new(vec![member], vec![], NonZero::new(2).expect("non-zero")),
            Role::StrataAdministrator,
        )));

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
        let action = MultisigAction::Update(UpdateAction::VerifyingKey(PredicateUpdate::new(
            PredicateKey::new(PredicateTypeId::Sp1Groth16, vec![0xde, 0xad, 0xbe, 0xef]),
            ProofType::Asm,
        )));

        let message = render_signing_message(&action, 5, Role::StrataAdministrator);
        assert!(message.contains("proof_type: Asm"));
        assert!(message.contains("predicate_type: Sp1Groth16"));
        assert!(message.contains("condition_len: 4"));
        assert!(message.contains("condition_hex: deadbeef"));
    }
}
