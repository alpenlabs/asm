//! Fork-based upgradeability primitives.
//!
//! The ASM upgrades EVM-style: STF logic is gated on named forks with L1
//! activation heights, so a single binary can execute both sides of an upgrade
//! boundary. The schedule is *not* part of committed state — it is baked into
//! each proving artifact (guest ELF / native host) and supplied to the worker
//! via params, with the invariant that every artifact agrees on the gate's
//! outcome at every height it executes (see `AsmStfParams`).

use serde::{Deserialize, Serialize};
use strata_identifiers::L1Height;

/// Identifies a named fork.
///
/// One variant per protocol upgrade, in activation order. Discriminants are
/// stable: they key persisted fork-activation records and are the raw fork
/// ids carried in ASM VK upgrade actions.
///
/// The id crosses two boundaries with opposite tolerances:
///
/// - Parse-time: ASM VK upgrade actions carry the raw id, not this enum, so an artifact predating a
///   fork can still parse and enact the upgrade that activates it — the wire format never requires
///   knowing the fork.
/// - Act-time: a consumer that must *apply* the fork's rules (the worker) maps the id via
///   [`TryFrom`]. An id it does not know is not skipped: it means the worker is running old
///   software past an upgrade it cannot execute, so it MUST halt rather than silently limp along on
///   stale rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ForkId {
    /// Placeholder for the first protocol upgrade; renamed once that upgrade
    /// is defined.
    Fork1 = 0,
}

impl From<ForkId> for u8 {
    fn from(fork: ForkId) -> Self {
        fork as u8
    }
}

impl From<ForkId> for u16 {
    fn from(fork: ForkId) -> Self {
        fork as u16
    }
}

impl TryFrom<u8> for ForkId {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ForkId::Fork1),
            invalid => Err(invalid),
        }
    }
}

impl TryFrom<u16> for ForkId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .ok()
            .and_then(|v| ForkId::try_from(v).ok())
            .ok_or(value)
    }
}

/// Activation heights for every named fork.
///
/// A fork with activation height `Some(n)` is active at L1 height `h` iff
/// `h >= n` — so `Some(0)` means active since genesis. `None` means disabled.
/// Proving artifacts bake one of the two extremes (`Some(0)` or `None` — an
/// artifact only ever executes one side of an upgrade boundary), while the
/// worker tracks the real activation height discovered from the ASM VK
/// upgrade log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkSchedule {
    /// Activation height of [`ForkId::Fork1`], or `None` if disabled.
    pub fork1: Option<L1Height>,
}

impl ForkSchedule {
    /// Schedule with every fork disabled (no activation height).
    pub const fn all_disabled() -> Self {
        Self { fork1: None }
    }

    /// Returns the activation height of `fork`, or `None` if disabled.
    pub fn activation_height_of(&self, fork: ForkId) -> Option<L1Height> {
        match fork {
            ForkId::Fork1 => self.fork1,
        }
    }

    /// Returns whether `fork` is active at L1 `height`.
    pub fn is_active(&self, fork: ForkId, height: L1Height) -> bool {
        self.activation_height_of(fork)
            .is_some_and(|activation| height >= activation)
    }

    /// Sets the activation height of `fork`.
    pub fn set_fork_activation(&mut self, fork: ForkId, height: L1Height) {
        match fork {
            ForkId::Fork1 => self.fork1 = Some(height),
        }
    }
}

impl Default for ForkSchedule {
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
/// plus discovered fork activations.
///
/// `Default` inherits [`ForkSchedule`]'s default: everything disabled.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmStfParams {
    /// Fork activation schedule.
    pub forks: ForkSchedule,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_active_boundaries() {
        let sched = ForkSchedule { fork1: Some(100) };
        assert!(!sched.is_active(ForkId::Fork1, 99));
        assert!(sched.is_active(ForkId::Fork1, 100));
        assert!(sched.is_active(ForkId::Fork1, 101));
    }

    #[test]
    fn zero_means_always_active() {
        let sched = ForkSchedule { fork1: Some(0) };
        assert!(sched.is_active(ForkId::Fork1, 0));
        assert!(sched.is_active(ForkId::Fork1, L1Height::MAX));
    }

    #[test]
    fn none_means_never_active() {
        let sched = ForkSchedule::all_disabled();
        assert_eq!(sched.activation_height_of(ForkId::Fork1), None);
        assert!(!sched.is_active(ForkId::Fork1, 0));
        assert!(!sched.is_active(ForkId::Fork1, L1Height::MAX));
    }

    #[test]
    fn set_fork_activation_overrides() {
        let mut sched = ForkSchedule::all_disabled();
        sched.set_fork_activation(ForkId::Fork1, 42);
        assert_eq!(sched.activation_height_of(ForkId::Fork1), Some(42));
        assert!(sched.is_active(ForkId::Fork1, 42));
        assert!(!sched.is_active(ForkId::Fork1, 41));
    }

    #[test]
    fn serde_roundtrip() {
        let params = AsmStfParams {
            forks: ForkSchedule { fork1: Some(7) },
        };
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, r#"{"forks":{"fork1":7}}"#);
        let back: AsmStfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);

        let disabled = AsmStfParams {
            forks: ForkSchedule::all_disabled(),
        };
        let json = serde_json::to_string(&disabled).unwrap();
        assert_eq!(json, r#"{"forks":{"fork1":null}}"#);
        let back: AsmStfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, disabled);
    }

    #[test]
    fn fork_id_serde_snake_case() {
        assert_eq!(serde_json::to_string(&ForkId::Fork1).unwrap(), r#""fork1""#);
    }

    /// Raw fork ids on the wire round-trip through the enum; unknown ids
    /// surface as errors instead of misparsing.
    #[test]
    fn fork_id_u16_roundtrip() {
        assert_eq!(u16::from(ForkId::Fork1), 0);
        assert_eq!(ForkId::try_from(0u16).unwrap(), ForkId::Fork1);
        assert_eq!(ForkId::try_from(0xFFFFu16), Err(0xFFFF));
    }
}
