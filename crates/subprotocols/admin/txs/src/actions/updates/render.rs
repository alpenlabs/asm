use strata_asm_params::Role;
use strata_crypto::{hash, threshold_signature::ThresholdConfigUpdate};
use strata_predicate::{PredicateKey, PredicateTypeId};

use crate::actions::{IndentedDetails, append_indexed_fields, role_label};

pub(super) fn multisig(
    role: Role,
    config: &ThresholdConfigUpdate,
    details: &mut IndentedDetails<'_>,
) {
    details.push(format!("Target Role: {}", role_label(role)));
    details.push(format!("New Threshold: {}", config.new_threshold()));
    append_indexed_fields(
        details,
        "Add Member",
        config
            .add_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
    append_indexed_fields(
        details,
        "Remove Member",
        config
            .remove_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
}

pub(super) fn predicate(label: &str, key: &PredicateKey, details: &mut IndentedDetails<'_>) {
    let predicate_type = PredicateTypeId::try_from(key.id())
        .expect("predicate type should be validated at construction");
    let condition = key.condition();
    details.push(format!("Proof Type: {label}"));
    details.push(format!("Predicate Type: {predicate_type}"));
    details.push(format!("Condition Len: {}", condition.len()));
    if condition.len() <= 32 {
        details.push(format!("Condition Hex: {}", hex::encode(condition)));
    } else {
        details.push(format!("Condition Hash: {:x}", hash::raw(condition)));
    }
}
