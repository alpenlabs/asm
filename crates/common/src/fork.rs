//! Fork-based upgradeability primitives.
//!
//! The ASM upgrades EVM-style: STF logic is gated on named forks with L1
//! activation heights, so a single binary can execute both sides of an upgrade
//! boundary. The schedule is *not* part of committed state — it is baked into
//! each proving artifact (guest ELF / native host) and supplied to the worker
//! via params, with the invariant that every artifact agrees on the gate's
//! outcome at every height it executes (see `StfParams`).

use serde::{Deserialize, Serialize};

/// Identifies a named fork.
///
/// One variant per protocol upgrade, in activation order. Discriminants are
/// stable: they key persisted fork-activation records and are the raw fork
/// ids carried in ASM VK upgrade actions. Actions carry the raw id rather
/// than this enum so that artifacts predating a fork can still parse and
/// enact the upgrade that activates it; consumers that act on the id (the
/// worker) map the ones they know via [`TryFrom`] and skip the rest.
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
/// A fork is active at L1 height `h` iff `h >= activation_height`. `0` means
/// active since genesis; [`u64::MAX`] means never active. Proving artifacts
/// bake one of those two extremes (an artifact only ever executes one side of
/// an upgrade boundary), while the worker tracks the real activation height
/// discovered from the ASM VK upgrade log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkSchedule {
    /// Activation height of [`ForkId::Fork1`].
    pub fork1: u64,
}

impl ForkSchedule {
    /// Schedule with every fork disabled (activation at [`u64::MAX`]).
    pub const fn all_disabled() -> Self {
        Self { fork1: u64::MAX }
    }

    /// Schedule with every fork active since genesis (activation at `0`).
    pub const fn all_enabled() -> Self {
        Self { fork1: 0 }
    }

    /// Returns the activation height of `fork`.
    pub fn activation_height(&self, fork: ForkId) -> u64 {
        match fork {
            ForkId::Fork1 => self.fork1,
        }
    }

    /// Returns whether `fork` is active at L1 `height`.
    pub fn is_active(&self, fork: ForkId, height: u64) -> bool {
        height >= self.activation_height(fork)
    }

    /// Sets the activation height of `fork`.
    pub fn activate_at(&mut self, fork: ForkId, height: u64) {
        match fork {
            ForkId::Fork1 => self.fork1 = height,
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
pub struct StfParams {
    /// Fork activation schedule.
    pub forks: ForkSchedule,
}

impl StfParams {
    /// Params with every fork active since genesis, matching current mainline
    /// behavior.
    pub const fn all_forks_enabled() -> Self {
        Self {
            forks: ForkSchedule::all_enabled(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_active_boundaries() {
        let sched = ForkSchedule { fork1: 100 };
        assert!(!sched.is_active(ForkId::Fork1, 99));
        assert!(sched.is_active(ForkId::Fork1, 100));
        assert!(sched.is_active(ForkId::Fork1, 101));
    }

    #[test]
    fn zero_means_always_active() {
        let sched = ForkSchedule { fork1: 0 };
        assert!(sched.is_active(ForkId::Fork1, 0));
        assert!(sched.is_active(ForkId::Fork1, u64::MAX));
    }

    #[test]
    fn max_means_never_active() {
        let sched = ForkSchedule::all_disabled();
        assert!(!sched.is_active(ForkId::Fork1, 0));
        assert!(!sched.is_active(ForkId::Fork1, u64::MAX - 1));
        // Degenerate boundary: is_active is a plain >= comparison.
        assert!(sched.is_active(ForkId::Fork1, u64::MAX));
    }

    #[test]
    fn activate_at_overrides() {
        let mut sched = ForkSchedule::all_disabled();
        sched.activate_at(ForkId::Fork1, 42);
        assert_eq!(sched.activation_height(ForkId::Fork1), 42);
        assert!(sched.is_active(ForkId::Fork1, 42));
        assert!(!sched.is_active(ForkId::Fork1, 41));
    }

    #[test]
    fn serde_roundtrip() {
        let params = StfParams {
            forks: ForkSchedule { fork1: 7 },
        };
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, r#"{"forks":{"fork1":7}}"#);
        let back: StfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
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
