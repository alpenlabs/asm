#![allow(unused_crate_dependencies)]
use std::{env, fs, path::PathBuf};

use k256::schnorr::{signature::Signer, Signature, SigningKey};
use ssz::{Decode, Encode};
use strata_asm_manifest_types::{compute_asm_manifests_hash, AsmManifest};
use strata_asm_proto_checkpoint_types::{
    CheckpointClaim, CheckpointPayload, CheckpointSidecar, CheckpointTip, L2BlockRange, OLLog,
    TerminalHeaderComplement,
};
use strata_crypto::hash;
use strata_identifiers::{Buf32, OLBlockCommitment, OLBlockId};
use strata_predicate::{PredicateKey, PredicateTypeId};

fn main() {
    let output = PathBuf::from(env::args().nth(1).expect("output directory"));
    fs::create_dir_all(&output).unwrap();
    let manifest = AsmManifest::from_ssz_bytes(
        &fs::read(env::args().nth(2).expect("baseline manifest")).unwrap(),
    )
    .unwrap();
    fs::write(output.join("manifest.ssz"), manifest.as_ssz_bytes()).unwrap();
    let from = CheckpointTip::new(
        0,
        99,
        OLBlockCommitment::new(0, OLBlockId::from(Buf32::from([3; 32]))),
    );
    let to = CheckpointTip::new(
        1,
        100,
        OLBlockCommitment::new(1, OLBlockId::from(Buf32::from([4; 32]))),
    );
    let logs: Vec<OLLog> = vec![];
    let diff = vec![5, 6, 7];
    let complement = TerminalHeaderComplement::new(
        123,
        OLBlockId::from(Buf32::from([3; 32])),
        Buf32::from([8; 32]),
        Buf32::from([9; 32]),
    );
    let claim = CheckpointClaim::new(
        to.epoch,
        L2BlockRange::new(from.l2_commitment, to.l2_commitment),
        compute_asm_manifests_hash(&[manifest]),
        hash::raw(&diff).into(),
        hash::raw(&logs.as_ssz_bytes()).into(),
        complement.compute_hash(),
    );
    let sidecar = CheckpointSidecar::new(diff, logs, complement).unwrap();
    let key = SigningKey::from_bytes(&[7; 32]).unwrap();
    let signature: Signature = key.sign(&claim.as_ssz_bytes());
    let predicate = PredicateKey::new(
        PredicateTypeId::Bip340Schnorr,
        key.verifying_key().to_bytes().to_vec(),
    );
    predicate
        .verify_claim_witness(&claim.as_ssz_bytes(), &signature.to_bytes())
        .unwrap();
    let payload = CheckpointPayload::new(to, sidecar, signature.to_bytes().to_vec()).unwrap();
    for (name, bytes) in [
        ("previous-tip.ssz", from.as_ssz_bytes()),
        ("checkpoint.ssz", payload.as_ssz_bytes()),
        ("claim.ssz", claim.as_ssz_bytes()),
        ("predicate.ssz", predicate.as_ssz_bytes()),
    ] {
        fs::write(output.join(name), bytes).unwrap();
    }
}
