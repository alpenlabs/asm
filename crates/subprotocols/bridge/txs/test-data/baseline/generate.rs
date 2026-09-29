//! Run only against baseline 45a1fa2 with its locked dependencies.
#![allow(unused_crate_dependencies)]

use std::{env, fs, path::PathBuf};

use bitcoin::{
    Amount,
    consensus::serialize,
    secp256k1::{Keypair, SECP256K1},
};
use strata_asm_proto_bridge_v1_txs::{
    deposit_request::{DrtHeaderAux, parse_drt},
    test_utils::create_test_deposit_request_tx,
};
use strata_codec::VarVec;

fn main() {
    let output = PathBuf::from(env::args().nth(1).expect("fixture output directory"));
    fs::create_dir_all(&output).unwrap();
    let recovery = Keypair::from_seckey_slice(SECP256K1, &[7; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    let internal = Keypair::from_seckey_slice(SECP256K1, &[8; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    for len in [0, 20, 42] {
        let destination = vec![0xab; len];
        let aux = DrtHeaderAux::new(recovery.serialize(), VarVec::from_vec(destination).unwrap())
            .unwrap();
        let tx = create_test_deposit_request_tx(&aux, internal, Amount::from_sat(100_000), 1008);
        let parsed = parse_drt(&tx).unwrap();
        assert_eq!(parsed.header_aux(), &aux);
        assert_eq!(parsed.deposit_request_output().inner(), &tx.output[1]);
        fs::write(
            output.join(format!("deposit-request-{len}.bin")),
            serialize(&tx),
        )
        .unwrap();
    }
}
