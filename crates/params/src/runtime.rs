//! Parameters of the per-block state transition function.

use serde::{Deserialize, Serialize};
use strata_asm_common::{AsmStfParams, SpecActivation};

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
    fn test_runtime_params_deserialize() {
        let params: AsmRuntimeParams =
            serde_json::from_str(r#"{"spec_activation":{"v1":5}}"#).unwrap();
        assert_eq!(params.stf_params().spec_activation.v1, Some(5));
    }
}
