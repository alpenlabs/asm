//! Moving bridge sections between section schemas.
//!
//! Rulesets before spec 2 store schema 0 through [`BridgeSubproto`](crate::BridgeSubproto).
//! Spec 2 stores schema 1 through [`BridgeSubprotoV3`], which records each assignment's
//! [`AssignmentStatus`](crate::AssignmentStatus). Spec 2's
//! [`prepare`](strata_asm_common::AsmSpec::prepare) runs [`migrate_bridge_section`] on a schema-0
//! parent before the section is loaded.

use strata_asm_common::{AsmError, SectionState, SectionStateExt, Subprotocol};
use strata_asm_proto_bridge_state::{BridgeStateV1, BridgeStateV2};

use crate::{BridgeSubprotoV1, BridgeSubprotoV3};

/// Decodes a bridge section stored under either section schema.
///
/// Schema-0 assignments decode as [`Active`](crate::AssignmentStatus::Active).
///
/// # Errors
///
/// Returns an error if the section belongs to another subprotocol, names an unknown schema, or
/// does not decode under the schema it names.
pub fn decode_bridge_section(section: &SectionState) -> Result<BridgeStateV1, AsmError> {
    if section.version == BridgeSubprotoV1::STATE_VERSION {
        section.try_to_state::<BridgeSubprotoV1>()
    } else {
        section
            .try_to_state::<BridgeSubprotoV3>()
            .map(BridgeStateV2::into_inner)
    }
}

/// Rewrites a schema-0 bridge section in schema 1, with every assignment active.
///
/// Schema 1 spends one more byte per assignment, so a section near the capacity limit may not
/// fit after migration. The section is left unchanged on error.
///
/// # Errors
///
/// Returns [`AsmError::SectionTooLarge`] if the migrated state exceeds the section capacity, or
/// a decoding error if the section is not a schema-0 bridge section.
pub fn migrate_bridge_section(section: &mut SectionState) -> Result<(), AsmError> {
    let state = section.try_to_state::<BridgeSubprotoV1>()?;
    *section = SectionState::from_state::<BridgeSubprotoV3>(&BridgeStateV2::from(state))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin_bosd::Descriptor;
    use ssz::Encode;
    use strata_asm_bridge_types::WithdrawalIntent;
    use strata_asm_proto_bridge_state::AssignmentStatus;
    use strata_asm_proto_bridge_txs::deposit::DepositInfo;
    use strata_identifiers::L1BlockCommitment;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::test_utils::{add_deposits_and_assignments, create_test_state};

    /// `MAX_SECTION_STATE_BYTES` in `strata-asm-state`'s schema.
    const MAX_SECTION_STATE_BYTES: usize = 1 << 20;

    fn v0_section(state: &BridgeStateV1) -> SectionState {
        SectionState::from_state::<BridgeSubprotoV1>(state).expect("test state fits the capacity")
    }

    /// A schema-0 section with live assignments becomes a schema-1 section that the new
    /// subprotocol loads, with every assignment active and the rest of the state unchanged.
    #[test]
    fn migrate_bridge_section_upgrades_v0_assignments_to_active() {
        let (mut state, _privkeys) = create_test_state();
        add_deposits_and_assignments(&mut state, 3);
        let mut section = v0_section(&state);
        assert!(
            section.try_to_state::<BridgeSubprotoV3>().is_err(),
            "the schema-1 subprotocol must not load a schema-0 section"
        );

        migrate_bridge_section(&mut section).expect("schema-0 section migrates");

        assert_eq!(section.version, BridgeSubprotoV3::STATE_VERSION);
        let migrated = section
            .try_to_state::<BridgeSubprotoV3>()
            .expect("migrated section loads under schema 1");
        assert_eq!(migrated.assignments().len(), 3);
        for assignment in migrated.assignments().assignments() {
            assert_eq!(assignment.status(), AssignmentStatus::Active);
        }
        assert_eq!(migrated.into_inner().as_ssz_bytes(), state.as_ssz_bytes());
    }

    /// Migration only accepts schema 0, so an already migrated section is refused rather than
    /// rewritten.
    #[test]
    fn migrate_bridge_section_rejects_schema_1_section() {
        let (state, _privkeys) = create_test_state();
        let mut section = v0_section(&state);
        migrate_bridge_section(&mut section).expect("schema-0 section migrates");
        let migrated = section.clone();

        assert!(matches!(
            migrate_bridge_section(&mut section),
            Err(AsmError::SectionVersionMismatch {
                expected: 0,
                actual: 1,
                ..
            })
        ));
        assert_eq!(section, migrated);
    }

    /// A schema-0 section that fits the capacity but outgrows it once every assignment gains its
    /// status byte fails with [`AsmError::SectionTooLarge`] and is left unchanged.
    #[test]
    fn migrate_bridge_section_reports_section_too_large() {
        assert!(SectionState::new(0, 0, vec![0; MAX_SECTION_STATE_BYTES]).is_ok());
        assert!(SectionState::new(0, 0, vec![0; MAX_SECTION_STATE_BYTES + 1]).is_err());

        let (mut state, _privkeys) = create_test_state();
        let mut arb = ArbitraryGenerator::new();
        let l1blk: L1BlockCommitment = arb.generate();

        // Schema 1 is schema 0 plus one byte per assignment. Each new assignment grows schema 0
        // by its entry and a 4-byte list offset, so tracking the length keeps the loop linear.
        // A fixed destination keeps every entry small, so the loop stops inside the window where
        // schema 0 still fits and schema 1 does not.
        let destination = Descriptor::new_p2wpkh(&[0xaa; 20]);
        let mut v0_len = state.ssz_bytes_len();
        let mut count = 0;
        while v0_len + count <= MAX_SECTION_STATE_BYTES {
            let mut info: DepositInfo = arb.generate();
            let deposit_idx = info.header_aux().deposit_idx();
            if state.assignments().get_assignment(deposit_idx).is_some() {
                continue;
            }
            info.set_amt(*state.denomination());
            if state.add_deposit(&info).is_err() {
                continue;
            }
            let mut intent: WithdrawalIntent = arb.generate();
            intent.amt = *state.denomination();
            intent.destination = destination.clone();
            let assignment = state
                .create_withdrawal_assignment(&intent, &l1blk)
                .expect("the only deposit backs the assignment");
            v0_len += assignment.ssz_bytes_len() - 1 + 4;
            count += 1;
            state.insert_withdrawal_assignment(assignment);
        }
        assert_eq!(state.ssz_bytes_len(), v0_len);
        assert!(v0_len <= MAX_SECTION_STATE_BYTES);

        let mut section = v0_section(&state);
        let original = section.clone();

        assert!(matches!(
            migrate_bridge_section(&mut section),
            Err(AsmError::SectionTooLarge { id, .. }) if id == BridgeSubprotoV3::ID
        ));
        assert_eq!(section, original);
    }

    /// Both schemas decode to the same state, and sections of other subprotocols or unknown
    /// schemas are refused rather than guessed at.
    #[test]
    fn decode_bridge_section_reads_both_schemas_and_rejects_others() {
        let (mut state, _privkeys) = create_test_state();
        add_deposits_and_assignments(&mut state, 2);
        let v0 = v0_section(&state);
        let mut v1 = v0.clone();
        migrate_bridge_section(&mut v1).expect("schema-0 section migrates");

        for section in [&v0, &v1] {
            let decoded = decode_bridge_section(section).expect("supported schema decodes");
            assert_eq!(decoded.as_ssz_bytes(), state.as_ssz_bytes());
        }

        let foreign = SectionState::new(BridgeSubprotoV1::ID + 1, 0, v0.data.to_vec())
            .expect("test state fits the capacity");
        assert!(matches!(
            decode_bridge_section(&foreign),
            Err(AsmError::SubprotoIdMismatch(_))
        ));

        let unknown = SectionState::new(BridgeSubprotoV1::ID, 2, v0.data.to_vec())
            .expect("test state fits the capacity");
        assert!(matches!(
            decode_bridge_section(&unknown),
            Err(AsmError::SectionVersionMismatch {
                expected: 1,
                actual: 2,
                ..
            })
        ));
    }
}
