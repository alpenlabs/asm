//! Frozen baseline transactions exercise parsing and Taproot lock construction together.

use bitcoin::{
    Amount, Transaction,
    consensus::{deserialize, serialize},
    secp256k1::{Keypair, SECP256K1},
};
use strata_codec::VarVec;

use crate::{
    deposit_request::{DrtHeaderAux, parse_drt},
    test_utils::create_test_deposit_request_tx,
};

#[test]
fn baseline_deposit_requests_preserve_metadata_and_locking_script() {
    let recovery = Keypair::from_seckey_slice(SECP256K1, &[7; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    let internal = Keypair::from_seckey_slice(SECP256K1, &[8; 32])
        .unwrap()
        .x_only_public_key()
        .0;
    let fixtures: [(usize, &[u8]); 3] = [
        (
            0,
            include_bytes!("../test-data/baseline/deposit-request-0.bin"),
        ),
        (
            20,
            include_bytes!("../test-data/baseline/deposit-request-20.bin"),
        ),
        (
            42,
            include_bytes!("../test-data/baseline/deposit-request-42.bin"),
        ),
    ];
    for (len, bytes) in fixtures {
        let tx: Transaction = deserialize(bytes).expect("baseline Bitcoin transaction decodes");
        let aux = DrtHeaderAux::new(
            recovery.serialize(),
            VarVec::from_vec(vec![0xab; len]).unwrap(),
        )
        .unwrap();
        let parsed = parse_drt(&tx).expect("baseline deposit request remains accepted");
        assert_eq!(parsed.header_aux(), &aux, "destination length {len}");
        assert_eq!(parsed.deposit_request_output().inner(), &tx.output[1]);
        assert_eq!(tx.output[1].value, Amount::from_sat(100_000));
        let rebuilt =
            create_test_deposit_request_tx(&aux, internal, Amount::from_sat(100_000), 1008);
        assert_eq!(
            serialize(&rebuilt),
            bytes,
            "baseline lock/tag bytes changed for destination length {len}"
        );
    }
}
