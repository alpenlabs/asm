//! Parameters of the per-block state transition function.

use serde::{Deserialize, Serialize};
use strata_asm_common::{AsmStfParams, ForkSchedule};

/// Runtime parameters of the state transition function.
///
/// `forks` is the base fork schedule the worker starts from — the part that,
/// on the proving side, is baked into guest programs as [`AsmStfParams`]. The
/// worker overlays it with activations discovered from enacted ASM VK
/// upgrades, each of which names the fork it activates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmRuntimeParams {
    /// Base fork activation schedule.
    pub forks: ForkSchedule,
}

impl AsmRuntimeParams {
    /// The STF-facing view of these params, before any dynamic activations.
    pub fn stf_params(&self) -> AsmStfParams {
        AsmStfParams {
            forks: self.forks.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_params_deserialize() {
        let params: AsmRuntimeParams = serde_json::from_str(r#"{"forks":{"fork1":5}}"#).unwrap();
        assert_eq!(params.stf_params().forks.fork1, Some(5));
    }
}
