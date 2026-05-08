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
    let predicate_type = match PredicateTypeId::try_from(key.id()) {
        Ok(id) => id.to_string(),
        Err(_) => format!("unknown ({})", key.id()),
    };
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

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_crypto::keys::compressed::CompressedPublicKey;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::actions::IndentedDetails;

    fn render_lines<F: FnOnce(&mut IndentedDetails<'_>)>(f: F) -> Vec<String> {
        let mut lines = Vec::new();
        let mut details = IndentedDetails::new(&mut lines);
        f(&mut details);
        lines
    }

    fn arb_pubkey() -> CompressedPublicKey {
        ArbitraryGenerator::new().generate()
    }

    fn pubkey_hex(key: &CompressedPublicKey) -> String {
        hex::encode(key.serialize())
    }

    #[test]
    fn multisig_renders_two_adds_and_two_removes() {
        let a1 = arb_pubkey();
        let a2 = arb_pubkey();
        let r1 = arb_pubkey();
        let r2 = arb_pubkey();
        let config = ThresholdConfigUpdate::new(
            vec![a1, a2],
            vec![r1, r2],
            NonZero::new(2).expect("non-zero"),
        );

        let lines = render_lines(|details| multisig(&config, details));

        assert_eq!(
            lines,
            vec![
                "  New Threshold: 2".to_string(),
                "  Members to Add: 2".to_string(),
                format!("  1. Add Member: {}", pubkey_hex(&a1)),
                format!("  2. Add Member: {}", pubkey_hex(&a2)),
                "  Members to Remove: 2".to_string(),
                format!("  1. Remove Member: {}", pubkey_hex(&r1)),
                format!("  2. Remove Member: {}", pubkey_hex(&r2)),
            ],
        );
    }

    #[test]
    fn multisig_renders_two_adds_and_no_removes() {
        let a1 = arb_pubkey();
        let a2 = arb_pubkey();
        let config =
            ThresholdConfigUpdate::new(vec![a1, a2], vec![], NonZero::new(2).expect("non-zero"));

        let lines = render_lines(|details| multisig(&config, details));

        assert_eq!(
            lines,
            vec![
                "  New Threshold: 2".to_string(),
                "  Members to Add: 2".to_string(),
                format!("  1. Add Member: {}", pubkey_hex(&a1)),
                format!("  2. Add Member: {}", pubkey_hex(&a2)),
                "  Members to Remove: 0".to_string(),
            ],
        );
    }

    #[test]
    fn multisig_renders_no_adds_and_two_removes() {
        let r1 = arb_pubkey();
        let r2 = arb_pubkey();
        let config =
            ThresholdConfigUpdate::new(vec![], vec![r1, r2], NonZero::new(1).expect("non-zero"));

        let lines = render_lines(|details| multisig(&config, details));

        assert_eq!(
            lines,
            vec![
                "  New Threshold: 1".to_string(),
                "  Members to Add: 0".to_string(),
                "  Members to Remove: 2".to_string(),
                format!("  1. Remove Member: {}", pubkey_hex(&r1)),
                format!("  2. Remove Member: {}", pubkey_hex(&r2)),
            ],
        );
    }

    #[test]
    fn multisig_renders_no_adds_and_no_removes() {
        let config = ThresholdConfigUpdate::new(vec![], vec![], NonZero::new(1).expect("non-zero"));

        let lines = render_lines(|details| multisig(&config, details));

        assert_eq!(
            lines,
            vec![
                "  New Threshold: 1".to_string(),
                "  Members to Add: 0".to_string(),
                "  Members to Remove: 0".to_string(),
            ],
        );
    }

    #[test]
    fn predicate_short_condition_uses_hex() {
        let condition = vec![0xab; 16];
        let key = PredicateKey::new(PredicateTypeId::AlwaysAccept, condition.clone());

        let lines = render_lines(|details| predicate(&key, details));

        assert_eq!(
            lines,
            vec![
                "  Predicate Type: AlwaysAccept".to_string(),
                format!("  Predicate Hex: {}", hex::encode(&condition)),
            ],
        );
    }

    #[test]
    fn predicate_at_32_byte_boundary_uses_hex() {
        let condition = vec![0xcd; 32];
        let key = PredicateKey::new(PredicateTypeId::Bip340Schnorr, condition.clone());

        let lines = render_lines(|details| predicate(&key, details));

        assert_eq!(
            lines,
            vec![
                "  Predicate Type: Bip340Schnorr".to_string(),
                format!("  Predicate Hex: {}", hex::encode(&condition)),
            ],
        );
    }

    #[test]
    fn predicate_long_condition_uses_hash() {
        let condition = vec![0x42; 33];
        let key = PredicateKey::new(PredicateTypeId::Sp1Groth16, condition.clone());

        let lines = render_lines(|details| predicate(&key, details));

        assert_eq!(
            lines,
            vec![
                "  Predicate Type: Sp1Groth16".to_string(),
                format!("  Predicate Hash: {:x}", hash::raw(&condition)),
            ],
        );
    }

    #[test]
    fn predicate_unknown_type_renders_raw_id() {
        use ssz::Decode;

        // SSZ container layout for `PredicateKey { id: u8, condition: VariableList<u8, 1024> }`:
        // [id (1 byte)][offset to condition (u32 LE, 4 bytes)][condition bytes]
        let condition = vec![0xab; 16];
        let mut bytes = vec![99u8];
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&condition);

        let key = PredicateKey::from_ssz_bytes(&bytes).expect("valid SSZ");
        assert_eq!(key.id(), 99);

        let lines = render_lines(|details| predicate(&key, details));

        assert_eq!(
            lines,
            vec![
                "  Predicate Type: unknown (99)".to_string(),
                format!("  Predicate Hex: {}", hex::encode(&condition)),
            ],
        );
    }

    #[test]
    fn predicate_empty_condition_uses_hex() {
        let key = PredicateKey::always_accept();

        let lines = render_lines(|details| predicate(&key, details));

        assert_eq!(
            lines,
            vec![
                "  Predicate Type: AlwaysAccept".to_string(),
                "  Predicate Hex: ".to_string(),
            ],
        );
    }

    #[test]
    fn append_indexed_fields_with_no_values_emits_only_count() {
        let lines = render_lines(|details| {
            append_indexed_fields(details, "Items", "Item", Vec::<String>::new());
        });

        assert_eq!(lines, vec!["  Items: 0".to_string()]);
    }

    #[test]
    fn append_indexed_fields_numbers_values_starting_at_one() {
        let values = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];

        let lines = render_lines(|details| {
            append_indexed_fields(details, "Things", "Thing", values);
        });

        assert_eq!(
            lines,
            vec![
                "  Things: 3".to_string(),
                "  1. Thing: alpha".to_string(),
                "  2. Thing: beta".to_string(),
                "  3. Thing: gamma".to_string(),
            ],
        );
    }
}
