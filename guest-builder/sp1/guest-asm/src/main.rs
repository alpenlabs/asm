#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use strata_asm_params::{AsmParams, SubprotocolInstance};
use strata_asm_proof_impl::statements::process_asm_stf;
use strata_asm_spec::StrataAsmSpec;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

fn main() {
    let spec = hardcoded_spec();
    process_asm_stf(&Sp1ZkVmEnv, &spec)
}
const SUBPROTOCOLS_JSON: &str = r#"
[
  {"Admin":{"strata_administrator":{"keys":["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],"threshold":1},"strata_sequencer_manager":{"keys":["03cf59a1a5ef092ced386f2651b610d3dd2cc6806bb74a8eab95c1f3b2f3d81772","02343edde4a056e00af99aa49de60df03859d1b79ebbc4f3f6da8fbd0053565de3"],"threshold":1},"confirmation_depth":144,"max_seqno_gap":10}},
  {"Checkpoint":{"sequencer_predicate":"Sp1Groth16","checkpoint_predicate":"AlwaysAccept","genesis_l1_height":3334849731,"genesis_ol_blkid":"c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"}},
  {"Bridge":{"operators":["02becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70"],"denomination":0,"assignment_duration":0,"operator_fee":0,"recovery_delay":0}}
]
"#;

const GENESIS_L1_VIEW_JSON: &str = r#"
{
  "blk": {
    "height": 50462976,
    "blkid": "0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"
  },
  "next_target": 656811300,
  "epoch_start_timestamp": 724183336,
  "last_11_timestamps": [
    791555372,
    858927408,
    926299444,
    993671480,
    1061043516,
    1128415552,
    1195787588,
    1263159624,
    1330531660,
    1397903696,
    1465275732
  ]
}
"#;

fn hardcoded_spec() -> StrataAsmSpec {
    let subprotocols: Vec<SubprotocolInstance> =
        serde_json::from_str(SUBPROTOCOLS_JSON).expect("failed to deserialize subprotocols");

    let params = AsmParams {
        // Equivalent to MagicBytes::new(*b"ALPN")
        magic: serde_json::from_str("\"ALPN\"").expect("failed to deserialize magic bytes"),
        // This remains hardcoded, but keeps the same shape used in proof-impl tests.
        l1_view: serde_json::from_str(GENESIS_L1_VIEW_JSON)
            .expect("failed to deserialize hardcoded genesis l1 view"),
        subprotocols,
    };

    StrataAsmSpec::from_asm_params(&params)
}
