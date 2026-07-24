//! Spec-versioned upgradeability primitives.
//!
//! The ASM upgrades EVM-style: STF logic is gated on spec versions with L1
//! activation heights, so a single binary can execute both sides of an upgrade
//! boundary. The activation schedule is *not* part of committed state — it is
//! baked into each proving artifact (guest ELF / native host) and supplied to
//! the worker via params, with the invariant that every artifact agrees on the
//! gate's outcome at every height it executes (see `AsmStfParams`).

use serde::{Deserialize, Serialize};
use strata_identifiers::L1Height;

/// Identifies a spec version.
///
/// One variant per protocol upgrade, in activation order. The numeric
/// discriminant is the stable identity: it keys persisted spec-activation
/// records (stored as the raw discriminant byte) and is the raw id carried in
/// ASM VK upgrade actions. The variant name is the human-readable form: it is
/// this type's serde representation (snake_case) and is mirrored by the
/// [`SpecActivation`] params field.
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

/// Activation heights for every spec version.
///
/// A version with activation height `Some(n)` is active at L1 height `h` iff
/// `h >= n` — so `Some(0)` means active since genesis. `None` means disabled.
/// Proving artifacts bake one of the two extremes (`Some(0)` or `None` — an
/// artifact only ever executes one side of an upgrade boundary), while the
/// worker tracks the real activation height discovered from the ASM VK
/// upgrade log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecActivation {
    /// Activation height of [`SpecId::V1`], or `None` if disabled.
    pub v1: Option<L1Height>,
}

impl SpecActivation {
    /// Schedule with every spec version disabled (no activation height).
    pub const fn all_disabled() -> Self {
        Self { v1: None }
    }

    /// Returns the activation height of `spec`, or `None` if disabled.
    pub fn activation_height_of(&self, spec: SpecId) -> Option<L1Height> {
        match spec {
            SpecId::V1 => self.v1,
        }
    }

    /// Returns whether `spec` is active at L1 `height`.
    pub fn is_active(&self, spec: SpecId, height: L1Height) -> bool {
        self.activation_height_of(spec)
            .is_some_and(|activation| height >= activation)
    }

    /// Sets the activation height of `spec`.
    pub fn set_activation(&mut self, spec: SpecId, height: L1Height) {
        match spec {
            SpecId::V1 => self.v1 = Some(height),
        }
    }
}

impl Default for SpecActivation {
    fn default() -> Self {
        Self::all_disabled()
    }
}

/// Protocol-rule parameters consumed by the STF, as opposed to the genesis
/// params that only seed the initial state.
///
/// Every executor of the STF carries its own copy: guest programs hardcode it
/// (so the proof's verifying key commits to it), native proving hosts bake it
/// into their closure, and the worker derives an effective copy from params
/// plus discovered spec activations.
///
/// `Default` inherits [`SpecActivation`]'s default: everything disabled.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmStfParams {
    /// Spec activation schedule.
    pub spec_activation: SpecActivation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_active_boundaries() {
        let activation = SpecActivation { v1: Some(100) };
        assert!(!activation.is_active(SpecId::V1, 99));
        assert!(activation.is_active(SpecId::V1, 100));
        assert!(activation.is_active(SpecId::V1, 101));
    }

    #[test]
    fn zero_means_always_active() {
        let activation = SpecActivation { v1: Some(0) };
        assert!(activation.is_active(SpecId::V1, 0));
        assert!(activation.is_active(SpecId::V1, L1Height::MAX));
    }

    #[test]
    fn none_means_never_active() {
        let activation = SpecActivation::all_disabled();
        assert_eq!(activation.activation_height_of(SpecId::V1), None);
        assert!(!activation.is_active(SpecId::V1, 0));
        assert!(!activation.is_active(SpecId::V1, L1Height::MAX));
    }

    #[test]
    fn set_activation_overrides() {
        let mut activation = SpecActivation::all_disabled();
        activation.set_activation(SpecId::V1, 42);
        assert_eq!(activation.activation_height_of(SpecId::V1), Some(42));
        assert!(activation.is_active(SpecId::V1, 42));
        assert!(!activation.is_active(SpecId::V1, 41));
    }

    #[test]
    fn serde_roundtrip() {
        let params = AsmStfParams {
            spec_activation: SpecActivation { v1: Some(7) },
        };
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, r#"{"spec_activation":{"v1":7}}"#);
        let back: AsmStfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);

        let disabled = AsmStfParams {
            spec_activation: SpecActivation::all_disabled(),
        };
        let json = serde_json::to_string(&disabled).unwrap();
        assert_eq!(json, r#"{"spec_activation":{"v1":null}}"#);
        let back: AsmStfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, disabled);
    }

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
