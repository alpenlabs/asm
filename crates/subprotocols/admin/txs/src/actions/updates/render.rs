use strata_crypto::{hash, threshold_signature::ThresholdConfigUpdate};
use strata_predicate::{PredicateKey, PredicateTypeId};

use crate::actions::IndentedDetails;

pub(super) fn multisig(config: &ThresholdConfigUpdate, details: &mut IndentedDetails<'_>) {
    details.push(format!("New Threshold: {}", config.new_threshold()));
    append_indexed_fields(
        details,
        "Members to Add",
        "Add Member",
        config
            .add_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
    append_indexed_fields(
        details,
        "Members to Remove",
        "Remove Member",
        config
            .remove_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
}

pub(super) fn predicate(key: &PredicateKey, details: &mut IndentedDetails<'_>) {
    let predicate_type = PredicateTypeId::try_from(key.id())
        .expect("predicate type should be validated at construction");
    let condition = key.condition();
    details.push(format!("Predicate Type: {predicate_type}"));
    if condition.len() <= 32 {
        details.push(format!("Predicate Hex: {}", hex::encode(condition)));
    } else {
        details.push(format!("Predicate Hash: {:x}", hash::raw(condition)));
    }
}

pub(super) fn append_indexed_fields(
    details: &mut IndentedDetails<'_>,
    count_label: &str,
    item_label: &str,
    values: impl IntoIterator<Item = String>,
) {
    let values: Vec<String> = values.into_iter().collect();
    details.push(format!("{count_label}: {}", values.len()));
    for (idx, value) in values.into_iter().enumerate() {
        details.push(format!("{}. {item_label}: {value}", idx + 1));
    }
}
