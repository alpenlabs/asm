//! Spec version identity.
//!
//! The ASM upgrades EVM-style: STF logic is gated on spec versions with L1
//! activation heights, so a single binary can execute both sides of an upgrade
//! boundary. This module names the versions; the activation schedule that
//! gates them lives with the runtime params as
//! [`SpecSchedule`](crate::SpecSchedule).

use core::convert::identity;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

/// Identifies a spec version.
///
/// One variant per protocol revision, in activation order, starting with the
/// genesis rules as [`SpecId::V0`]. The numeric discriminant is the stable
/// identity: it keys persisted spec-activation records and orders versions,
/// making "the successor of a version" well-defined. Discriminants MUST stay
/// contiguous from 0 — [`SpecSchedule`](crate::SpecSchedule) indexes its
/// activation heights by discriminant, so adding a variant is only this one
/// line, but a gap would desynchronize the schedule. The variant name is the
/// human-readable form: it is this type's serde representation (snake_case)
/// and keys the schedule's serialized form.
///
/// Nothing on the wire carries the id: an ASM VK upgrade action knows only
/// the new verifying key, so an artifact predating a spec version can still
/// parse and enact the upgrade that activates it. The consumer that must
/// *apply* the version's rules (the worker) instead derives each upgrade's
/// activating version via
/// [`SpecSchedule::schedule_successor`](crate::SpecSchedule::schedule_successor).
/// A successor it cannot map is not skipped: it means the worker is running
/// old software past an upgrade it cannot execute, so it MUST halt rather
/// than silently limp along on stale rules.
///
/// The primitive conversions are derived so they cannot go stale when a
/// variant is added; [`TryFrom<u16>`] errs with the raw id it has no variant
/// for.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    IntoPrimitive,
    TryFromPrimitive,
)]
#[serde(rename_all = "snake_case")]
#[num_enum(error_type(name = u16, constructor = identity))]
#[repr(u16)]
pub enum SpecId {
    /// Genesis spec version: the rules in force from the genesis anchor
    /// onward, active since genesis in every schedule.
    V0 = 0,

    /// First protocol upgrade; placeholder name until that upgrade is
    /// defined.
    V1 = 1,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serde is the human-readable form (the variant name). The stable numeric
    /// identity used for persistence and the wire is exercised by
    /// [`spec_id_u16_roundtrip`] instead.
    #[test]
    fn spec_id_serde_is_the_variant_name() {
        assert_eq!(serde_json::to_string(&SpecId::V0).unwrap(), r#""v0""#);
        assert_eq!(
            serde_json::from_str::<SpecId>(r#""v1""#).unwrap(),
            SpecId::V1
        );
        assert!(serde_json::from_str::<SpecId>(r#""nope""#).is_err());
    }

    /// Raw spec ids on the wire round-trip through the enum; unknown ids
    /// surface as errors instead of misparsing. Pinning the *first* unknown
    /// discriminant also guards contiguity: when a new variant lands, this
    /// assertion fails and must be bumped alongside it.
    #[test]
    fn spec_id_u16_roundtrip() {
        assert_eq!(u16::from(SpecId::V0), 0);
        assert_eq!(u16::from(SpecId::V1), 1);
        assert_eq!(SpecId::try_from(0u16).unwrap(), SpecId::V0);
        assert_eq!(SpecId::try_from(1u16).unwrap(), SpecId::V1);
        assert_eq!(SpecId::try_from(2u16), Err(2));
        assert_eq!(SpecId::try_from(0xFFFFu16), Err(0xFFFF));
    }
}
