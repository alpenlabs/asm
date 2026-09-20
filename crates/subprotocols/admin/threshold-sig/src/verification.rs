//! Verification of a signature set against a threshold configuration.

mod ecdsa;

use crate::{
    config::ThresholdConfig,
    errors::ThresholdSignatureError,
    signature::{IndexedSignature, SignatureSet},
};

/// Verifies a set of ECDSA signatures against a threshold configuration.
///
/// The set is first rebuilt through [`SignatureSet::new`] so that a repeated signer index is
/// rejected before it can be counted twice. The signature count must then meet the
/// configured threshold, and every signature must recover to a key whose P2WPKH address is
/// the one its index names.
///
/// # Errors
///
/// Returns [`ThresholdSignatureError::DuplicateSignerIndex`] for a repeated index,
/// [`ThresholdSignatureError::InsufficientSignatures`] when the threshold is not met,
/// [`ThresholdSignatureError::SignerIndexOutOfBounds`] for an index outside the signer list,
/// and [`ThresholdSignatureError::InvalidSignature`] when a signature does not recover to the
/// expected signer.
pub fn verify_threshold_signatures(
    config: &ThresholdConfig,
    signatures: &[IndexedSignature],
    message_hash: &[u8; 32],
) -> Result<(), ThresholdSignatureError> {
    let signature_set = SignatureSet::new(signatures.to_vec())?;

    if signature_set.len() < config.threshold() as usize {
        return Err(ThresholdSignatureError::InsufficientSignatures {
            provided: signature_set.len(),
            required: config.threshold() as usize,
        });
    }

    ecdsa::verify_ecdsa_signatures(config, &signature_set, message_hash)
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::hashes::{Hash as _, hash160};
    use secp256k1::{PublicKey, SECP256K1, SecretKey};

    use super::*;
    use crate::address::P2wpkhAddress;

    /// Returns a secret key and the address of the signer that holds it.
    fn generate_signer(seed: u8) -> (SecretKey, P2wpkhAddress) {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = seed.max(1);
        let sk = SecretKey::from_slice(&sk_bytes).expect("seed is a valid scalar");
        let signer = P2wpkhAddress::from_pubkey(&PublicKey::from_secret_key(SECP256K1, &sk));
        (sk, signer)
    }

    fn nonzero(value: u8) -> NonZero<u8> {
        NonZero::new(value).expect("test threshold is non-zero")
    }

    #[test]
    fn verifies_a_satisfied_threshold() {
        let (sk1, s1) = generate_signer(1);
        let (sk2, s2) = generate_signer(2);
        let (_, s3) = generate_signer(3);

        let config = ThresholdConfig::try_new(vec![s1, s2, s3], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let signatures = vec![
            IndexedSignature::new(0, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
            IndexedSignature::new(1, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk2)),
        ];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Ok(())
        );
    }

    #[test]
    fn rejects_too_few_signatures() {
        let (_, s1) = generate_signer(1);
        let (sk2, s2) = generate_signer(2);
        let (_, s3) = generate_signer(3);

        let config = ThresholdConfig::try_new(vec![s1, s2, s3], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let signatures = vec![IndexedSignature::new(
            1,
            ecdsa::sign_ecdsa_recoverable(&message_hash, &sk2),
        )];

        assert!(matches!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Err(ThresholdSignatureError::InsufficientSignatures { .. })
        ));
    }

    #[test]
    fn rejects_a_signature_over_another_message() {
        let (sk1, s1) = generate_signer(1);
        let (sk2, s2) = generate_signer(2);

        let config = ThresholdConfig::try_new(vec![s1, s2], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let signatures = vec![
            IndexedSignature::new(0, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
            IndexedSignature::new(1, ecdsa::sign_ecdsa_recoverable(&[0xCD; 32], &sk2)),
        ];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Err(ThresholdSignatureError::InvalidSignature { index: 1 })
        );
    }

    #[test]
    fn rejects_a_signature_filed_under_another_signers_index() {
        let (sk1, s1) = generate_signer(1);
        let (_, s2) = generate_signer(2);

        let config = ThresholdConfig::try_new(vec![s1, s2], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        // Both signatures are from sk1, but the second claims to be signer 1.
        let signatures = vec![
            IndexedSignature::new(0, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
            IndexedSignature::new(1, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
        ];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Err(ThresholdSignatureError::InvalidSignature { index: 1 })
        );
    }

    #[test]
    fn rejects_an_index_outside_the_signer_list() {
        let (sk1, s1) = generate_signer(1);
        let (sk2, s2) = generate_signer(2);

        let config = ThresholdConfig::try_new(vec![s1, s2], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let signatures = vec![
            IndexedSignature::new(0, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
            IndexedSignature::new(99, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk2)),
        ];

        assert!(matches!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Err(ThresholdSignatureError::SignerIndexOutOfBounds { index: 99, .. })
        ));
    }

    #[test]
    fn rejects_a_repeated_signer() {
        let (sk1, s1) = generate_signer(1);
        let (_, s2) = generate_signer(2);

        let config = ThresholdConfig::try_new(vec![s1, s2], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let signatures = vec![
            IndexedSignature::new(0, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
            IndexedSignature::new(0, ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1)),
        ];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Err(ThresholdSignatureError::DuplicateSignerIndex(0))
        );
    }

    #[test]
    fn verifies_bip137_signatures() {
        let (sk1, s1) = generate_signer(1);
        let (sk2, s2) = generate_signer(2);
        let (_, s3) = generate_signer(3);

        let config = ThresholdConfig::try_new(vec![s1, s2, s3], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let sig0 = ecdsa::sign_ecdsa_bip137(&message_hash, &sk1);
        let sig1 = ecdsa::sign_ecdsa_bip137(&message_hash, &sk2);
        assert!((31..=34).contains(&sig0[0]));
        assert!((31..=34).contains(&sig1[0]));

        let signatures = vec![
            IndexedSignature::new(0, sig0),
            IndexedSignature::new(1, sig1),
        ];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Ok(())
        );
    }

    #[test]
    fn verifies_a_mix_of_raw_and_bip137_signatures() {
        let (sk1, s1) = generate_signer(1);
        let (sk2, s2) = generate_signer(2);
        let (_, s3) = generate_signer(3);

        let config = ThresholdConfig::try_new(vec![s1, s2, s3], nonzero(2)).unwrap();
        let message_hash = [0xAB; 32];

        let sig0 = ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1);
        let sig1 = ecdsa::sign_ecdsa_bip137(&message_hash, &sk2);
        assert!(sig0[0] <= 3);
        assert!(sig1[0] >= 31);

        let signatures = vec![
            IndexedSignature::new(0, sig0),
            IndexedSignature::new(1, sig1),
        ];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Ok(())
        );
    }

    /// P2WPKH is only defined over compressed keys, so a signer's address is always the hash
    /// of the compressed point. A signer configured under the uncompressed hash can never
    /// authorize anything, whatever BIP-137 header its wallet emits.
    #[test]
    fn rejects_a_signer_configured_under_the_uncompressed_key_hash() {
        let (sk1, _) = generate_signer(1);
        let pubkey = PublicKey::from_secret_key(SECP256K1, &sk1);
        let uncompressed = P2wpkhAddress::from_byte_array(
            hash160::Hash::hash(&pubkey.serialize_uncompressed()).to_byte_array(),
        );

        let config = ThresholdConfig::try_new(vec![uncompressed], nonzero(1)).unwrap();
        let message_hash = [0xAB; 32];

        let signatures = vec![IndexedSignature::new(
            0,
            ecdsa::sign_ecdsa_recoverable(&message_hash, &sk1),
        )];

        assert_eq!(
            verify_threshold_signatures(&config, &signatures, &message_hash),
            Err(ThresholdSignatureError::InvalidSignature { index: 0 })
        );
    }
}
