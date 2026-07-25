//! Parameters of the per-block state transition function.
//!
//! The activation schedule is *not* part of committed state — it is baked into
//! each proving artifact (guest ELF / native host) and supplied to the worker
//! via params, with the invariant that every artifact agrees on every gate's
//! outcome at every height it executes (see [`AsmStfParams`]).

use serde::{Deserialize, Serialize};
use strata_identifiers::L1Height;

use crate::spec_id::SpecId;

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

/// Runtime parameters of the state transition function.
///
/// `spec_activation` is the base activation schedule the worker starts from —
/// the part that, on the proving side, is baked into guest programs as
/// [`AsmStfParams`]. The worker overlays it with activations discovered from
/// enacted ASM VK upgrades, each of which names the spec version it activates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmRuntimeParams {
    /// Base spec activation schedule.
    pub spec_activation: SpecActivation,
}

impl AsmRuntimeParams {
    /// The STF-facing view of these params, before any dynamic activations.
    pub fn stf_params(&self) -> AsmStfParams {
        AsmStfParams {
            spec_activation: self.spec_activation.clone(),
        }
    }
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
    fn stf_params_serde_roundtrip() {
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

    #[test]
    fn test_runtime_params_deserialize() {
        let params: AsmRuntimeParams =
            serde_json::from_str(r#"{"spec_activation":{"v1":5}}"#).unwrap();
        assert_eq!(params.stf_params().spec_activation.v1, Some(5));
    }
}
