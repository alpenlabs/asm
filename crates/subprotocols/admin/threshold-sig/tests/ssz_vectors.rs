//! Fixed SSZ vectors for the administration threshold types.
//!
//! [`ThresholdConfig`] and [`SignatureSet`] sit inside administration subprotocol state and
//! inside the signed admin payload, so their encodings are consensus-critical. The vectors
//! below were produced by the codec these types previously delegated to, in strata-crypto.
//! They pin the encoding across the move into this crate, and would catch a later edit to
//! `ssz/threshold.ssz` that silently changed the wire format.

// The crate's own dependencies are not all needed by this integration test.
use std::{fmt::Debug, num::NonZero};

#[cfg(feature = "arbitrary")]
use arbitrary as _;
use borsh as _;
use proptest as _;
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use serde as _;
use serde_json as _;
use ssz::{Decode, Encode};
use ssz_derive as _;
use ssz_primitives as _;
use ssz_types as _;
use strata_asm_admin_threshold_sig::{
    CompressedPublicKey, IndexedSignature, SignatureSet, ThresholdConfig, ThresholdConfigUpdate,
};
use thiserror as _;
use tree_hash as _;
use tree_hash_derive as _;

/// Derives a deterministic test key from a seed.
fn key(i: u32) -> CompressedPublicKey {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[28..32].copy_from_slice(&(i + 1).to_be_bytes());
    let sk = SecretKey::from_slice(&sk_bytes).expect("seed is a valid scalar");
    CompressedPublicKey::from(PublicKey::from_secret_key(SECP256K1, &sk))
}

/// Builds a 65-byte BIP-137 signature that is distinguishable by index.
fn signature(index: u8) -> [u8; 65] {
    let mut bytes = [0u8; 65];
    bytes[0] = 27;
    bytes[1] = index;
    bytes[64] = index;
    bytes
}

fn nonzero(value: u8) -> NonZero<u8> {
    NonZero::new(value).expect("test threshold is non-zero")
}

/// Asserts that `value` encodes to `expected_hex` and decodes back from it.
fn assert_vector<T>(value: T, expected_hex: &str)
where
    T: Encode + Decode + PartialEq + Debug,
{
    let expected = hex::decode(expected_hex).expect("vector is valid hex");

    assert_eq!(hex::encode(value.as_ssz_bytes()), expected_hex);
    assert_eq!(value.ssz_bytes_len(), expected.len());
    assert_eq!(T::from_ssz_bytes(&expected).expect("vector decodes"), value);
}

#[test]
fn compressed_public_key_vector() {
    assert_vector(
        key(0),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
}

#[test]
fn threshold_config_vectors() {
    assert_vector(
        ThresholdConfig::try_new(vec![key(0)], nonzero(1)).unwrap(),
        "05000000010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    assert_vector(
        ThresholdConfig::try_new((0..3).map(key).collect(), nonzero(2)).unwrap(),
        "05000000020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    );
}

#[test]
fn threshold_config_update_vectors() {
    assert_vector(
        ThresholdConfigUpdate::try_new(vec![], vec![], nonzero(1)).unwrap(),
        "090000000900000001",
    );
    assert_vector(
        ThresholdConfigUpdate::try_new((0..2).map(key).collect(), vec![key(100)], nonzero(2))
            .unwrap(),
        "090000004b000000020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3",
    );
}

#[test]
fn indexed_signature_vector() {
    assert_vector(
        IndexedSignature::new(3, signature(3)),
        "031b03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
    );
}

#[test]
fn signature_set_vectors() {
    assert_vector(SignatureSet::empty(), "04000000");
    assert_vector(
        SignatureSet::new(vec![
            IndexedSignature::new(0, signature(0)),
            IndexedSignature::new(3, signature(3)),
        ])
        .unwrap(),
        "04000000001b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000031b03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
    );
}
