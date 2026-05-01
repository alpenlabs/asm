use strata_asm_params::Role;
use strata_crypto::{hash, threshold_signature::ThresholdConfigUpdate};
use strata_predicate::{PredicateKey, PredicateTypeId};

use crate::signing_message::{append_indexed_fields, role_label};

pub(super) fn multisig(role: Role, config: &ThresholdConfigUpdate, lines: &mut Vec<String>) {
    lines.push(format!("target_role: {}", role_label(role)));
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

pub(super) fn predicate(label: &str, key: &PredicateKey, lines: &mut Vec<String>) {
    let predicate_type = PredicateTypeId::try_from(key.id())
        .expect("predicate type should be validated at construction");
    let condition = key.condition();
    lines.push(format!("proof_type: {label}"));
    lines.push(format!("predicate_type: {predicate_type}"));
    lines.push(format!("condition_len: {}", condition.len()));
    if condition.len() <= 32 {
        lines.push(format!("condition_hex: {}", hex::encode(condition)));
    } else {
        lines.push(format!("condition_hash: {:x}", hash::raw(condition)));
    }
}
