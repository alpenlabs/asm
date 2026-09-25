//! Parameter fixtures shared by the crate's tests.

/// Parameter file the deserialization tests read, anchored on regtest.
///
/// Originally generated from an arbitrary instance with seed [0..256].
pub(crate) fn regtest_params_json() -> &'static str {
    r#"
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
      "signers": [
        "bcrt1qzg7mfwfw4rxt4qu3jred7fd5c3ty3lcj7vk892"
      ],
      "threshold": 1
    },
    "strata_sequencer_manager": {
      "signers": [
        "bcrt1qrm8582v73hqguhvnduxtz5dlplkc7p8sxge4kz",
        "bcrt1qanymu6ywqcvx60h7trfzvjufthwvgw45d3usjz"
      ],
      "threshold": 1
    },
    "alpen_administrator": {
      "signers": [
        "bcrt1qzg7mfwfw4rxt4qu3jred7fd5c3ty3lcj7vk892"
      ],
      "threshold": 1
    },
    "strata_security_council": {
      "signers": [
        "bcrt1qzg7mfwfw4rxt4qu3jred7fd5c3ty3lcj7vk892"
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
      "safe_harbor_address_update": 144
    },
    "max_seqno_gap": 10
  }
},
{
  "Checkpoint": {
    "sequencer_key": "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
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
    "safe_harbor_address": "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  }
}
  ]
}
"#
}
