//! Converting the released administration state into this crate's layout.
//!
//! The conversion lives here, in the crate that defines the *new* layout, and
//! depends on the crate that defines the old one. Reversed, every frozen layout
//! would accrete a dependency on each layout that succeeded it, and a crate that
//! must never change would be edited on every future upgrade.
//!
//! Deciding *when* to convert is the framework's job, not this module's — see
//! `strata_asm_common::prepare_state`.

use std::collections::BTreeSet;

use ssz::{Decode, Encode};
use strata_asm_proto_admin_txs::actions::{UpdateAction, UpdateId};
use strata_asm_proto_admin_v0::AdministrationSubprotoState as AdministrationSubprotoStateV0;
use strata_identifiers::L1Height;
use thiserror::Error;

use crate::{AdministrationSubprotoState, queued_update::QueuedUpdate};

/// Failure to convert released administration state into the current layout.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdminMigrationError {
    /// A carried field did not decode into its current counterpart.
    ///
    /// Every field carried across this boundary is supposed to be structurally
    /// identical, differing only in which crate defines it. This reports the
    /// case where that stopped being true, rather than letting a silent shape
    /// change through.
    #[error("released administration field `{field}` does not match its current shape: {reason}")]
    FieldShapeChanged {
        /// The field being carried.
        field: &'static str,
        /// The decode failure.
        reason: String,
    },

    /// The released queue contains more OL predicate rotations than the
    /// successor's single pending-transition slot can safely represent.
    ///
    /// Activation heights cannot make two queued rotations safe: promotion of
    /// the first depends on a later valid checkpoint and has no bounded L1
    /// completion height.
    #[error(
        "released administration state has {count} queued OL STF VK updates; the successor supports at most one outstanding rotation"
    )]
    TooManyQueuedOlStfVkUpdates {
        /// Number of OL predicate rotations found in the released queue.
        count: usize,
    },

    /// The released queue contains more than one ASM predicate rotation for one activation block.
    #[error(
        "released administration state has several ASM STF VK updates scheduled for L1 height {activation_height}; one block can hand over only one predicate"
    )]
    ConflictingQueuedAsmStfVkUpdates {
        /// Activation height claimed by more than one rotation.
        activation_height: L1Height,
    },

    /// A queued update should already have enacted in the predecessor state.
    #[error(
        "released administration update {update_id} activates at L1 height {activation_height}, which is not after the stored boundary height {boundary_height}"
    )]
    OverdueQueuedUpdate {
        /// Queued update that violated the predecessor's drain invariant.
        update_id: UpdateId,
        /// Height at which the update was supposed to enact.
        activation_height: L1Height,
        /// Height of the stored predecessor anchor being migrated.
        boundary_height: L1Height,
    },
}

/// Transfers a value between two structurally identical types defined in
/// different crates, by way of the encoding they are supposed to share.
///
/// This is the honest way to carry a field across a frozen/current crate
/// boundary: the claim "these are the same shape" is exactly what SSZ decoding
/// checks, so a divergence surfaces here instead of corrupting state.
fn carry<A, B>(value: &A, field: &'static str) -> Result<B, AdminMigrationError>
where
    A: Encode,
    B: Decode,
{
    B::from_ssz_bytes(&value.as_ssz_bytes()).map_err(|error| {
        AdminMigrationError::FieldShapeChanged {
            field,
            reason: format!("{error:?}"),
        }
    })
}

/// Converts released administration state into the current layout.
///
/// One field is genuinely new: `ol_transition_pending`, which can only take
/// `false` across the boundary because the released protocol had no representation
/// for an enacted OL predicate rotation awaiting activation. Released rotations can
/// still be waiting in the administration queue. At most one OL rotation is carried
/// because checkpoint state has one pending slot. ASM rotations at distinct heights
/// are all carried; only duplicate activation heights are rejected because one block
/// has one predicate handover.
///
/// Appending it is what advances this section's codec version: the container
/// holds variable-size fields, so a new fixed-size field enlarges the fixed part
/// and shifts every offset. The encoding therefore changes even though no
/// carried value does, which is why this cannot be a byte-level append.
pub fn migrate_from_v0(
    old: &AdministrationSubprotoStateV0,
    boundary_height: L1Height,
) -> Result<AdministrationSubprotoState, AdminMigrationError> {
    let queued: Vec<QueuedUpdate> = carry(&old.queued().to_vec(), "queued")?;
    if let Some(overdue) = queued
        .iter()
        .find(|queued| queued.activation_height() <= boundary_height)
    {
        return Err(AdminMigrationError::OverdueQueuedUpdate {
            update_id: *overdue.id(),
            activation_height: overdue.activation_height(),
            boundary_height,
        });
    }
    let queued_ol_rotations = queued
        .iter()
        .filter(|queued| matches!(queued.action(), UpdateAction::OlStfVk(_)))
        .count();
    if queued_ol_rotations > 1 {
        return Err(AdminMigrationError::TooManyQueuedOlStfVkUpdates {
            count: queued_ol_rotations,
        });
    }
    let mut asm_activation_heights = BTreeSet::new();
    for queued in queued
        .iter()
        .filter(|queued| matches!(queued.action(), UpdateAction::AsmStfVk(_)))
    {
        let activation_height = queued.activation_height();
        if !asm_activation_heights.insert(activation_height) {
            return Err(AdminMigrationError::ConflictingQueuedAsmStfVkUpdates {
                activation_height,
            });
        }
    }

    Ok(AdministrationSubprotoState::from_parts(
        carry(&old.authorities().to_vec(), "authorities")?,
        queued,
        carry(&old.next_update_id(), "next_update_id")?,
        // Defined in the shared admin-types crate, so this is the same type on
        // both sides and needs no transfer.
        old.confirmation_depths().clone(),
        old.max_seqno_gap(),
        // No rotation can be outstanding across the boundary: the released
        // protocol could not represent one.
        false,
    ))
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};
    use strata_asm_admin_types::AdministrationInitConfig;
    use strata_asm_proto_admin_txs::actions::updates::{AsmStfVkUpdate, OlStfVkUpdate};
    use strata_asm_proto_admin_v0::QueuedUpdate as QueuedUpdateV0;
    use strata_identifiers::L1Height;
    use strata_predicate::{PredicateKey, PredicateTypeId};
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    fn released() -> AdministrationSubprotoStateV0 {
        let config: AdministrationInitConfig = ArbitraryGenerator::new().generate();
        AdministrationSubprotoStateV0::new(&config)
    }

    fn enqueue_released_ol_rotation(
        state: &mut AdministrationSubprotoStateV0,
        seed: u8,
        activation_height: L1Height,
    ) {
        let predicate = PredicateKey::try_new(PredicateTypeId::Sp1Groth16, vec![seed; 32])
            .expect("test predicate is within the condition limit");
        let current = QueuedUpdate::new(
            state.next_update_id(),
            UpdateAction::OlStfVk(OlStfVkUpdate::new(predicate)),
            activation_height,
        );
        let released = QueuedUpdateV0::from_ssz_bytes(&current.as_ssz_bytes())
            .expect("released and successor queued actions have the same wire shape");
        state.enqueue(released);
        state.increment_next_update_id();
    }

    fn enqueue_released_asm_rotation(
        state: &mut AdministrationSubprotoStateV0,
        seed: u8,
        activation_height: L1Height,
    ) {
        let predicate = PredicateKey::try_new(PredicateTypeId::Sp1Groth16, vec![seed; 32])
            .expect("test predicate is within the condition limit");
        let current = QueuedUpdate::new(
            state.next_update_id(),
            UpdateAction::AsmStfVk(AsmStfVkUpdate::new(predicate)),
            activation_height,
        );
        let released = QueuedUpdateV0::from_ssz_bytes(&current.as_ssz_bytes())
            .expect("released and successor queued actions have the same wire shape");
        state.enqueue(released);
        state.increment_next_update_id();
    }

    /// Every field the released layout had reaches the current one, and the one
    /// field it did not have takes the only value it could.
    #[test]
    fn carries_released_fields_and_defaults_the_new_flag() {
        let old = released();
        let new = migrate_from_v0(&old, 0).expect("structurally identical fields carry across");

        assert_eq!(new.queued().len(), old.queued().len());
        assert_eq!(new.max_seqno_gap(), old.max_seqno_gap());
        assert_eq!(new.next_update_id(), old.next_update_id());
        assert!(
            !new.ol_transition_pending(),
            "the released protocol could not represent an outstanding rotation",
        );
    }

    #[test]
    fn zero_queued_ol_rotations_leave_the_successor_slot_clear() {
        let new =
            migrate_from_v0(&released(), 0).expect("an empty rotation queue is representable");

        assert!(!new.has_outstanding_ol_stf_vk_update());
        assert!(!new.ol_transition_pending());
    }

    #[test]
    fn one_queued_ol_rotation_is_carried_as_the_single_outstanding_rotation() {
        let mut old = released();
        enqueue_released_ol_rotation(&mut old, 0x11, 500);

        let new = migrate_from_v0(&old, 499).expect("one queued rotation is representable");

        assert_eq!(new.queued().len(), 1);
        assert!(matches!(new.queued()[0].action(), UpdateAction::OlStfVk(_)));
        assert!(new.has_outstanding_ol_stf_vk_update());
        assert!(
            !new.ol_transition_pending(),
            "the rotation remains queued; it has not enacted yet",
        );
    }

    #[test]
    fn two_queued_ol_rotations_are_rejected_at_the_boundary() {
        let mut old = released();
        enqueue_released_ol_rotation(&mut old, 0x11, 500);
        // A distant activation height is still unsafe because promotion of the
        // first transition is checkpoint-driven and has no bounded L1 height.
        enqueue_released_ol_rotation(&mut old, 0x22, 10_000);

        assert_eq!(
            migrate_from_v0(&old, 499),
            Err(AdminMigrationError::TooManyQueuedOlStfVkUpdates { count: 2 }),
        );
    }

    #[test]
    fn one_queued_asm_rotation_is_carried_at_its_activation_height() {
        let mut old = released();
        enqueue_released_asm_rotation(&mut old, 0x11, 500);

        let new = migrate_from_v0(&old, 499).expect("one queued ASM rotation is representable");

        assert_eq!(new.queued().len(), 1);
        assert!(matches!(
            new.queued()[0].action(),
            UpdateAction::AsmStfVk(_)
        ));
        assert!(new.has_asm_stf_vk_update_at(500));
    }

    #[test]
    fn queued_asm_rotations_at_distinct_heights_are_carried() {
        let mut old = released();
        enqueue_released_asm_rotation(&mut old, 0x11, 500);
        enqueue_released_asm_rotation(&mut old, 0x22, 10_000);

        let new = migrate_from_v0(&old, 499).expect("distinct blocks have distinct handover slots");
        assert_eq!(new.queued().len(), 2);
        assert!(new.has_asm_stf_vk_update_at(500));
        assert!(new.has_asm_stf_vk_update_at(10_000));
    }

    #[test]
    fn queued_asm_rotations_at_the_same_height_are_rejected() {
        let mut old = released();
        enqueue_released_asm_rotation(&mut old, 0x11, 500);
        enqueue_released_asm_rotation(&mut old, 0x22, 500);

        assert_eq!(
            migrate_from_v0(&old, 499),
            Err(AdminMigrationError::ConflictingQueuedAsmStfVkUpdates {
                activation_height: 500,
            }),
        );
    }

    #[test]
    fn an_update_due_at_or_before_the_boundary_is_rejected() {
        let mut old = released();
        enqueue_released_asm_rotation(&mut old, 0x11, 500);

        assert_eq!(
            migrate_from_v0(&old, 500),
            Err(AdminMigrationError::OverdueQueuedUpdate {
                update_id: 0,
                activation_height: 500,
                boundary_height: 500,
            }),
        );
    }

    /// Why this section's codec version advances: appending a fixed-size field
    /// to a container that holds variable-size ones enlarges the fixed part and
    /// shifts every offset, so the encodings differ even though every carried
    /// value is equal.
    #[test]
    fn the_two_layouts_do_not_share_an_encoding() {
        let old = released();
        let new = migrate_from_v0(&old, 0).expect("converts");

        assert_ne!(
            old.as_ssz_bytes(),
            new.as_ssz_bytes(),
            "the appended field must change the encoding",
        );
    }
}
