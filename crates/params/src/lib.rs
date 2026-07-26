//! Configuration parameters for the Anchor State Machine (ASM).
//!
//! Provides [`AsmParams`], split into [`AsmGenesisParams`] (L1 magic bytes,
//! genesis L1 view and per-subprotocol configuration, consumed once to build
//! the genesis state) and [`AsmRuntimeParams`] (spec activation schedule
//! driving the per-block state transition function).

mod genesis;
mod runtime;
mod spec_id;
mod subprotocols;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
pub use genesis::AsmGenesisParams;
pub use runtime::{AsmRuntimeParams, AsmStfParams, SpecSchedule, SpecScheduleError};
use serde::{Deserialize, Serialize};
pub use spec_id::SpecId;
pub use subprotocols::{
    AdminTxType, AdministrationInitConfig, BridgeInitConfig, CheckpointInitConfig,
    ConfirmationDepths, Role, SubprotocolInstance, UpdateTxType,
};

/// Top-level parameters for an ASM instance.
///
/// Split by consumer: [`AsmGenesisParams`] is only used to construct the
/// genesis anchor state, while [`AsmRuntimeParams`] configures the state
/// transition function for every block. Both are flattened in the serialized
/// form, so the params file is a single flat object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmParams {
    /// Parameters consumed once, at genesis state construction.
    #[serde(flatten)]
    pub genesis: AsmGenesisParams,

    /// Parameters of the per-block state transition function.
    #[serde(flatten)]
    pub runtime: AsmRuntimeParams,
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AsmParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            genesis: AsmGenesisParams::arbitrary(u)?,
            runtime: AsmRuntimeParams {
                spec_schedule: SpecSchedule::genesis(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asm_params_deserialize_from_raw_json() {
        // Static JSON generated from arbitrary instance with seed [0..256]
        let raw_json = r#"
{
  "magic": "ALPN",
  "anchor": {
    "block": {
      "height": 50462976,
      "blkid": "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"
    },
    "next_target": 656811300,
    "epoch_start_timestamp": 724183336,
    "network": "regtest"
  },
  "subprotocols": [
    {
      "Admin": {
        "strata_administrator": {
          "keys": [
            "02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"
          ],
          "threshold": 1
        },
        "strata_sequencer_manager": {
          "keys": [
            "03cf59a1a5ef092ced386f2651b610d3dd2cc6806bb74a8eab95c1f3b2f3d81772",
            "02343edde4a056e00af99aa49de60df03859d1b79ebbc4f3f6da8fbd0053565de3"
          ],
          "threshold": 1
        },
        "alpen_administrator": {
          "keys": [
            "02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"
          ],
          "threshold": 1
        },
        "strata_security_council": {
          "keys": [
            "02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"
          ],
          "threshold": 1
        },
        "confirmation_depths": {
          "strata_admin_multisig_update": 144,
          "strata_seq_manager_multisig_update": 144,
          "alpen_admin_multisig_update": 144,
          "strata_security_council_multisig_update": 144,
          "operator_update": 144,
          "sequencer_update": 144,
          "ol_stf_vk_update": 144,
          "asm_stf_vk_update": 144,
          "ee_stf_vk_update": 144,
          "defcon3": 144,
          "safe_harbour_address_update": 144
        },
        "max_seqno_gap": 10
      }
    },
    {
      "Checkpoint": {
        "sequencer_predicate": "Sp1Groth16",
        "checkpoint_predicate": "AlwaysAccept",
        "genesis_l1_height": 3334849731,
        "genesis_ol_blkid": "c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"
      }
    },
    {
      "Bridge": {
        "operators": [
          "02becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70"
        ],
        "denomination": 0,
        "assignment_duration": 0,
        "operator_fee": 0,
        "recovery_delay": 0,
        "safe_harbour_address": "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      }
    }
  ],
  "spec_activation": {
    "v0": 0
  }
}
"#;

        let params: AsmParams =
            serde_json::from_str(raw_json).expect("deserialization from raw JSON should succeed");
        assert_eq!(params.runtime.spec_schedule, SpecSchedule::genesis());
    }

    #[cfg(feature = "arbitrary")]
    mod proptest_arbitrary {
        use arbitrary::{Arbitrary, Unstructured};
        use proptest::{collection, prelude::*};

        use super::*;

        proptest! {
            #[test]
            fn test_arbitrary(seed in collection::vec(any::<u8>(), 0..4096)) {
                let mut u = Unstructured::new(&seed);
                let res = AsmParams::arbitrary(&mut u);
                prop_assert!(res.is_ok());
            }
        }
    }
}
