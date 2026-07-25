//! Spec version identity.
//!
//! The ASM upgrades EVM-style: STF logic is gated on spec versions with L1
//! activation heights, so a single binary can execute both sides of an upgrade
//! boundary. This module names the versions; the activation schedule that
//! gates them lives with the runtime params as
//! [`SpecActivation`](crate::SpecActivation).

use serde::{Deserialize, Serialize};

/// Identifies a spec version.
///
/// One variant per protocol upgrade, in activation order. The numeric
/// discriminant is the stable identity: it keys persisted spec-activation
/// records (stored as the raw discriminant byte) and is the raw id carried in
/// ASM VK upgrade actions. The variant name is the human-readable form: it is
/// this type's serde representation (snake_case) and is mirrored by the
/// [`SpecActivation`](crate::SpecActivation) params field.
///
/// The id crosses two boundaries with opposite tolerances:
///
/// - Parse-time: ASM VK upgrade actions carry the raw id, not this enum, so an artifact predating a
///   spec version can still parse and enact the upgrade that activates it — the wire format never
///   requires knowing the version.
/// - Act-time: a consumer that must *apply* the version's rules (the worker) maps the id via
///   [`TryFrom`]. An id it does not know is not skipped: it means the worker is running old
///   software past an upgrade it cannot execute, so it MUST halt rather than silently limp along on
///   stale rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum SpecId {
    /// First spec revision after genesis. Genesis rules are simply "no spec
    /// version active".
    V1 = 0,
}

impl From<SpecId> for u8 {
    fn from(spec: SpecId) -> Self {
        spec as u8
    }
}

impl From<SpecId> for u16 {
    fn from(spec: SpecId) -> Self {
        spec as u16
    }
}

impl TryFrom<u8> for SpecId {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SpecId::V1),
            invalid => Err(invalid),
        }
    }
}

impl TryFrom<u16> for SpecId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .ok()
            .and_then(|v| SpecId::try_from(v).ok())
            .ok_or(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serde is the human-readable form (the variant name). The stable numeric
    /// identity used for persistence and the wire is exercised by
    /// [`spec_id_u16_roundtrip`] instead.
    #[test]
    fn spec_id_serde_is_the_variant_name() {
        assert_eq!(serde_json::to_string(&SpecId::V1).unwrap(), r#""v1""#);
        assert_eq!(
            serde_json::from_str::<SpecId>(r#""v1""#).unwrap(),
            SpecId::V1
        );
        assert!(serde_json::from_str::<SpecId>(r#""nope""#).is_err());
    }

    /// Raw spec ids on the wire round-trip through the enum; unknown ids
    /// surface as errors instead of misparsing.
    #[test]
    fn spec_id_u16_roundtrip() {
        assert_eq!(u16::from(SpecId::V1), 0);
        assert_eq!(SpecId::try_from(0u16).unwrap(), SpecId::V1);
        assert_eq!(SpecId::try_from(0xFFFFu16), Err(0xFFFF));
    }
}
