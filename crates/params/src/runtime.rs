//! Parameters of the per-block state transition function.
//!
//! The activation schedule is *not* part of committed state — it is baked into
//! each proving artifact (guest ELF / native host) and supplied to the worker
//! via params, with the invariant that every artifact agrees on every gate's
//! outcome at every height it executes (see [`AsmStfParams`]).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use strata_identifiers::L1Height;
use thiserror::Error;

use crate::spec_id::SpecId;

/// The spec activation schedule: which versions are scheduled and from which
/// L1 height each one applies.
///
/// [`SpecId::V0`] is the genesis version, always active from height 0; the
/// schedule only tracks the upgrades after it, as the activation heights of a
/// contiguous run of successors (`upgrades[i]` belongs to the version with
/// discriminant `i + 1`). Versions activate strictly in succession, so a
/// gapped schedule ("v2 scheduled, v1 disabled") is unrepresentable, and a
/// new [`SpecId`] variant needs no change here — every method derives its
/// answer from the discriminant.
///
/// A version with activation height `n` is active at L1 height `h` iff
/// `h >= n`; versions past the scheduled run are disabled. Proving artifacts
/// bake one of the two extremes (`0` or unscheduled — an artifact only ever
/// executes one side of an upgrade boundary), while the worker tracks the
/// real activation heights discovered from the ASM VK upgrade log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SpecScheduleRepr", into = "SpecScheduleRepr")]
pub struct SpecSchedule {
    /// Activation height of each scheduled post-genesis version, indexed by
    /// predecessor count: `upgrades[i]` activates discriminant `i + 1`.
    upgrades: Vec<L1Height>,
}

/// A schedule update that would violate [`SpecSchedule`]'s invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SpecScheduleError {
    /// [`SpecId::V0`] is the genesis version: it is always active from height
    /// 0 and can be neither rescheduled nor disabled.
    #[error(
        "v0 is the genesis version, always active from height 0; it cannot be rescheduled or disabled"
    )]
    GenesisFixed,

    /// Scheduling `spec` while its predecessor is unscheduled would leave a
    /// gap in the activation sequence.
    #[error(
        "cannot schedule {spec:?} while its predecessor is unscheduled (latest scheduled: {latest:?})"
    )]
    Gap {
        /// The version whose scheduling was rejected.
        spec: SpecId,
        /// The newest scheduled version at the time of the attempt.
        latest: SpecId,
    },
}

impl SpecSchedule {
    /// The genesis schedule: [`SpecId::V0`] active since genesis, every later
    /// version unscheduled until an ASM VK upgrade activates it.
    pub const fn genesis() -> Self {
        Self {
            upgrades: Vec::new(),
        }
    }

    /// Returns the newest scheduled version (regardless of whether its
    /// activation height has been reached). Its successor is the version the
    /// next ASM VK upgrade activates.
    pub fn latest_scheduled(&self) -> SpecId {
        SpecId::try_from(self.upgrades.len() as u16)
            .expect("SpecSchedule invariant: every scheduled version has a SpecId variant")
    }

    /// Returns the activation height of `spec`, or `None` if unscheduled.
    pub fn activation_height_of(&self, spec: SpecId) -> Option<L1Height> {
        match u16::from(spec) {
            0 => Some(0),
            d => self.upgrades.get(usize::from(d) - 1).copied(),
        }
    }

    /// Returns whether `spec` is active at L1 `height`.
    pub fn is_active(&self, spec: SpecId, height: L1Height) -> bool {
        self.activation_height_of(spec)
            .is_some_and(|activation| height >= activation)
    }

    /// Schedules the successor of the newest scheduled version at `height`
    /// and returns which version that is.
    ///
    /// This is the discovery-side entry point: an enacted ASM VK upgrade does
    /// not name the version it activates (the wire only carries the new VK),
    /// so the activating version is *defined* as the successor. Errs with the
    /// successor's raw id when this binary has no [`SpecId`] variant for it —
    /// the caller is running old software past an upgrade it cannot execute.
    pub fn schedule_successor(&mut self, height: L1Height) -> Result<SpecId, u16> {
        let successor = SpecId::try_from(self.upgrades.len() as u16 + 1)?;
        self.upgrades.push(height);
        Ok(successor)
    }

    /// Schedules `spec` at `height`, overwriting its height if it is already
    /// scheduled.
    ///
    /// This is the replay-side entry point, for re-applying a persisted
    /// activation record (which *does* name its version) on top of a base
    /// schedule. Unlike [`Self::schedule_successor`] it accepts already-
    /// scheduled versions — the discovered height overrides the base — but
    /// still rejects anything that would break the invariants: rescheduling
    /// [`SpecId::V0`] or skipping past an unscheduled predecessor.
    pub fn schedule(&mut self, spec: SpecId, height: L1Height) -> Result<(), SpecScheduleError> {
        let idx = match usize::from(u16::from(spec)).checked_sub(1) {
            None => return Err(SpecScheduleError::GenesisFixed),
            Some(idx) => idx,
        };
        if idx > self.upgrades.len() {
            return Err(SpecScheduleError::Gap {
                spec,
                latest: self.latest_scheduled(),
            });
        }
        match self.upgrades.get_mut(idx) {
            Some(slot) => *slot = height,
            None => self.upgrades.push(height),
        }
        Ok(())
    }
}

impl Default for SpecSchedule {
    fn default() -> Self {
        Self::genesis()
    }
}

/// Serialized form of [`SpecSchedule`]: one entry per known version, `null`
/// when unscheduled (e.g. `{"v0": 0, "v1": null}`). Kept for params-file
/// compatibility with the former per-version struct; conversion back
/// re-validates the invariants, so a hand-edited gapped or v0-disabled
/// schedule is rejected at load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct SpecScheduleRepr(BTreeMap<SpecId, Option<L1Height>>);

/// Every known version, in discriminant order.
fn known_versions() -> impl Iterator<Item = SpecId> {
    (0u16..).map_while(|d| SpecId::try_from(d).ok())
}

impl From<SpecSchedule> for SpecScheduleRepr {
    fn from(schedule: SpecSchedule) -> Self {
        Self(
            known_versions()
                .map(|spec| (spec, schedule.activation_height_of(spec)))
                .collect(),
        )
    }
}

impl TryFrom<SpecScheduleRepr> for SpecSchedule {
    type Error = SpecScheduleError;

    fn try_from(repr: SpecScheduleRepr) -> Result<Self, Self::Error> {
        let height_of = |spec| repr.0.get(&spec).copied().flatten();
        if height_of(SpecId::V0) != Some(0) {
            return Err(SpecScheduleError::GenesisFixed);
        }
        let mut schedule = SpecSchedule::genesis();
        for spec in known_versions().skip(1) {
            match height_of(spec) {
                // An unscheduled version ends the run; `schedule` rejects any
                // scheduled one after it as a gap.
                None => continue,
                Some(height) => schedule.schedule(spec, height)?,
            }
        }
        Ok(schedule)
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
/// `Default` inherits [`SpecSchedule`]'s default: the genesis schedule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmStfParams {
    /// Spec activation schedule. The serde key keeps the name the params
    /// format was born with.
    #[serde(rename = "spec_activation")]
    pub spec_schedule: SpecSchedule,
}

/// Runtime parameters of the state transition function.
///
/// `spec_schedule` is the base activation schedule the worker starts from —
/// the part that, on the proving side, is baked into guest programs as
/// [`AsmStfParams`]. The worker overlays it with activations discovered from
/// enacted ASM VK upgrades, each of which activates the successor of the
/// newest scheduled version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmRuntimeParams {
    /// Base spec activation schedule. The serde key keeps the name the params
    /// format was born with.
    #[serde(rename = "spec_activation")]
    pub spec_schedule: SpecSchedule,
}

impl AsmRuntimeParams {
    /// The STF-facing view of these params, before any dynamic activations.
    pub fn stf_params(&self) -> AsmStfParams {
        AsmStfParams {
            spec_schedule: self.spec_schedule.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A schedule with `SpecId::V1` activating at `height`.
    fn v1_at(height: L1Height) -> SpecSchedule {
        let mut schedule = SpecSchedule::genesis();
        assert_eq!(schedule.schedule_successor(height), Ok(SpecId::V1));
        schedule
    }

    #[test]
    fn is_active_boundaries() {
        let schedule = v1_at(100);
        assert!(!schedule.is_active(SpecId::V1, 99));
        assert!(schedule.is_active(SpecId::V1, 100));
        assert!(schedule.is_active(SpecId::V1, 101));
    }

    #[test]
    fn v0_is_always_active() {
        let schedule = SpecSchedule::genesis();
        assert_eq!(schedule.activation_height_of(SpecId::V0), Some(0));
        assert!(schedule.is_active(SpecId::V0, 0));
        assert!(schedule.is_active(SpecId::V0, L1Height::MAX));
    }

    #[test]
    fn unscheduled_means_never_active() {
        let schedule = SpecSchedule::genesis();
        assert_eq!(schedule.activation_height_of(SpecId::V1), None);
        assert!(!schedule.is_active(SpecId::V1, 0));
        assert!(!schedule.is_active(SpecId::V1, L1Height::MAX));
    }

    #[test]
    fn latest_scheduled_is_the_newest_scheduled_version() {
        assert_eq!(SpecSchedule::genesis().latest_scheduled(), SpecId::V0);
        // A scheduled-but-unreached height still counts: the successor is
        // relative to what the schedule knows, not to what is active yet.
        assert_eq!(v1_at(L1Height::MAX).latest_scheduled(), SpecId::V1);
    }

    #[test]
    fn schedule_successor_chains_and_errs_past_known_versions() {
        let mut schedule = SpecSchedule::genesis();
        assert_eq!(schedule.schedule_successor(42), Ok(SpecId::V1));
        assert_eq!(schedule.activation_height_of(SpecId::V1), Some(42));
        // Every known version is scheduled, so the next successor's raw id
        // has no variant.
        assert_eq!(schedule.schedule_successor(43), Err(2));
        assert_eq!(schedule, v1_at(42), "failed call must not mutate");
    }

    #[test]
    fn schedule_overwrites_but_pins_genesis() {
        let mut schedule = v1_at(42);
        schedule.schedule(SpecId::V1, 100).unwrap();
        assert_eq!(schedule.activation_height_of(SpecId::V1), Some(100));
        assert_eq!(
            schedule.schedule(SpecId::V0, 7),
            Err(SpecScheduleError::GenesisFixed)
        );
    }

    #[test]
    fn serde_keeps_the_per_version_map_format() {
        let params = AsmStfParams {
            spec_schedule: v1_at(7),
        };
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, r#"{"spec_activation":{"v0":0,"v1":7}}"#);
        let back: AsmStfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);

        let genesis = AsmStfParams::default();
        let json = serde_json::to_string(&genesis).unwrap();
        assert_eq!(json, r#"{"spec_activation":{"v0":0,"v1":null}}"#);
        let back: AsmStfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, genesis);
    }

    #[test]
    fn deserialize_rejects_invalid_schedules() {
        // V0 disabled, missing, or moved off genesis.
        for json in [
            r#"{"v0":null,"v1":null}"#,
            r#"{"v1":7}"#,
            r#"{"v0":5,"v1":null}"#,
        ] {
            assert!(
                serde_json::from_str::<SpecSchedule>(json).is_err(),
                "{json}"
            );
        }
        // A version this binary has no variant for.
        assert!(serde_json::from_str::<SpecSchedule>(r#"{"v0":0,"v7":9}"#).is_err());
    }

    #[test]
    fn test_runtime_params_deserialize() {
        let params: AsmRuntimeParams =
            serde_json::from_str(r#"{"spec_activation":{"v0":0,"v1":5}}"#).unwrap();
        let schedule = params.stf_params().spec_schedule;
        assert_eq!(schedule.activation_height_of(SpecId::V0), Some(0));
        assert_eq!(schedule.activation_height_of(SpecId::V1), Some(5));
    }
}
