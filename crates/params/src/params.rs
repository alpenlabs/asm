#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use serde::{Deserialize, Serialize};
use strata_asm_admin_types::AdministrationInitConfig;
use strata_asm_bridge_types::BridgeInitConfig;
use strata_asm_checkpoint_types::CheckpointInitConfig;
use strata_btc_verification::L1Anchor;
use strata_l1_txfmt::MagicBytes;

/// Genesis configuration for a Strata ASM chain.
///
/// Consumed by the STF only when constructing the chain's initial state. The
/// runner may retain and expose it for inspection, but does not consult it for
/// later subprotocol dispatch.
///
/// Each subprotocol config is a required, named field rather than an entry in a
/// list. Which subprotocols run is fixed by the specification's pipeline, so a
/// list could only express states no specification can execute — a missing
/// config, a duplicate, or one for a subprotocol that is not in the pipeline.
/// Naming the fields makes those unrepresentable, and turns a bad genesis file
/// into a deserialization error that names the field instead of a panic during
/// genesis construction.
///
/// `deny_unknown_fields` is deliberate on both paths that read this type. When
/// loading a genesis file it catches a misspelled field that would otherwise
/// take a silent default, in a file every node has to agree on. When a client
/// decodes a `getParams` response it means an older client fails loudly instead
/// of dropping a field it does not recognize, which here could be the value
/// that decides which rules the chain follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrataGenesisConfig {
    /// SPS-50 magic bytes that identify protocol transactions on L1.
    pub magic: MagicBytes,

    /// L1 anchor point after which L1 processing begins.
    ///
    /// Captures everything needed to initialize
    /// [`HeaderVerificationState`](strata_btc_verification::HeaderVerificationState) and
    /// begin validating subsequent L1 headers.
    pub anchor: L1Anchor,

    /// Initial Administration subprotocol configuration.
    pub admin: AdministrationInitConfig,

    /// Initial Checkpoint subprotocol configuration.
    pub checkpoint: CheckpointInitConfig,

    /// Initial Bridge subprotocol configuration.
    pub bridge: BridgeInitConfig,
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for StrataGenesisConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        use strata_identifiers::L1BlockCommitment;

        let networks = [
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ];
        let network = *u.choose(&networks)?;

        let block = L1BlockCommitment::arbitrary(u)?;
        let anchor = L1Anchor {
            block,
            next_target: u.arbitrary()?,
            epoch_start_timestamp: u.arbitrary()?,
            network,
        };

        Ok(Self {
            magic: MagicBytes::new(*b"ALPN"),
            anchor,
            admin: AdministrationInitConfig::arbitrary(u)?,
            checkpoint: CheckpointInitConfig::arbitrary(u)?,
            bridge: BridgeInitConfig::arbitrary(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_config_deserialize_from_raw_json() {
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
  "admin": {
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
  },
  "checkpoint": {
    "sequencer_predicate": "Sp1Groth16",
    "checkpoint_predicate": "AlwaysAccept",
    "genesis_l1_height": 3334849731,
    "genesis_ol_blkid": "c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"
  },
  "bridge": {
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
"#;

        let _config: StrataGenesisConfig =
            serde_json::from_str(raw_json).expect("deserialization from raw JSON should succeed");
    }

    /// A stray field is refused and named, so a `subprotocols` key left over from
    /// the old shape cannot ride along unnoticed. A file that actually lacks the
    /// named configs is caught by the test below, not by this one.
    #[test]
    fn a_pre_flatten_params_file_is_rejected() {
        let mut json = minimal_json();
        json.as_object_mut()
            .expect("object")
            .insert("subprotocols".to_owned(), serde_json::json!([]));

        let error = serde_json::from_value::<StrataGenesisConfig>(json)
            .expect_err("an unknown field must be refused");
        assert!(
            error.to_string().contains("subprotocols"),
            "the error should name the offending field, got: {error}"
        );
    }

    /// Every subprotocol config is required, so a file missing one fails to parse
    /// instead of panicking during genesis construction.
    #[test]
    fn a_missing_subprotocol_config_is_a_parse_error() {
        for field in ["admin", "checkpoint", "bridge"] {
            let mut json = minimal_json();
            json.as_object_mut().expect("object").remove(field);

            let error = serde_json::from_value::<StrataGenesisConfig>(json)
                .expect_err("a missing subprotocol config must be refused");
            assert!(
                error.to_string().contains(field),
                "the error should name the missing field, got: {error}"
            );
        }
    }

    /// Duplicate named fields are rejected instead of silently choosing one
    /// genesis configuration over another.
    #[test]
    fn a_duplicate_genesis_field_is_a_parse_error() {
        let serialized = serde_json::to_string(&minimal_json()).expect("valid JSON value");
        let duplicated = serialized.replacen(
            "\"magic\":\"ALPN\"",
            "\"magic\":\"ALPN\",\"magic\":\"ALPN\"",
            1,
        );
        assert_ne!(duplicated, serialized, "test must insert a duplicate field");

        let error = serde_json::from_str::<StrataGenesisConfig>(&duplicated)
            .expect_err("a duplicate field must be refused");
        assert!(
            error.to_string().contains("duplicate field `magic`"),
            "the error should name the duplicate field, got: {error}",
        );
    }

    /// A valid config as a mutable `Value` the tests above perturb one field at
    /// a time.
    fn minimal_json() -> serde_json::Value {
        serde_json::json!({
            "magic": "ALPN",
            "anchor": {
                "block": {
                    "height": 0,
                    "blkid": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                "next_target": 486604799,
                "epoch_start_timestamp": 1231006505,
                "network": "regtest"
            },
            "admin": {
                "strata_administrator": {
                    "keys": ["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],
                    "threshold": 1
                },
                "strata_sequencer_manager": {
                    "keys": ["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],
                    "threshold": 1
                },
                "alpen_administrator": {
                    "keys": ["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],
                    "threshold": 1
                },
                "strata_security_council": {
                    "keys": ["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],
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
            },
            "checkpoint": {
                "sequencer_predicate": "AlwaysAccept",
                "checkpoint_predicate": "AlwaysAccept",
                "genesis_l1_height": 0,
                "genesis_ol_blkid": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "bridge": {
                "operators": ["02becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70"],
                "denomination": 0,
                "assignment_duration": 0,
                "operator_fee": 0,
                "recovery_delay": 0,
                "safe_harbour_address": "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            }
        })
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
                let res = StrataGenesisConfig::arbitrary(&mut u);
                prop_assert!(res.is_ok());
            }
        }
    }
}
