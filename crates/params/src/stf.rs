//! Configuration of the per-block state transition function.

use serde::{Deserialize, Serialize};
use strata_asm_common::{ForkSchedule, StfParams};

/// Configuration of the state transition function.
///
/// `forks` is the base fork schedule the worker starts from — the part that,
/// on the proving side, is baked into guest programs as [`StfParams`]. The
/// worker overlays it with activations discovered from enacted ASM VK
/// upgrades, each of which names the fork it activates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StfConfig {
    /// Base fork activation schedule.
    pub forks: ForkSchedule,
}

impl StfConfig {
    /// The STF-facing view of this config, before any dynamic activations.
    pub fn stf_params(&self) -> StfParams {
        StfParams {
            forks: self.forks.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stf_config_deserialize() {
        let cfg: StfConfig = serde_json::from_str(r#"{"forks":{"fork1":5}}"#).unwrap();
        assert_eq!(cfg.stf_params().forks.fork1, 5);
    }
}
