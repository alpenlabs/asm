use std::ops::Deref;

use secp256k1::{Parity, PublicKey, SECP256K1, SecretKey, ffi::XOnlyPublicKey};

/// Represents a secret key whose x-only public key has even parity.
///
/// Converting from a [`SecretKey`] negates the key when its x-only public key has odd parity,
/// so the resulting [`EvenSecretKey`] always yields even parity.
#[derive(Debug, Clone, Copy)]
pub struct EvenSecretKey(SecretKey);

impl Deref for EvenSecretKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<SecretKey> for EvenSecretKey {
    fn as_ref(&self) -> &SecretKey {
        &self.0
    }
}

impl From<SecretKey> for EvenSecretKey {
    fn from(value: SecretKey) -> Self {
        match value.x_only_public_key(SECP256K1).1 == Parity::Odd {
            true => Self(value.negate()),
            false => Self(value),
        }
    }
}

impl From<EvenSecretKey> for SecretKey {
    fn from(value: EvenSecretKey) -> Self {
        value.0
    }
}

/// Represents a public key whose x-only public key has even parity.
///
/// Converting from a [`PublicKey`] negates the key when its x-only public key has odd parity,
/// so the resulting [`EvenPublicKey`] always yields even parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvenPublicKey(PublicKey);

/// Ensures a keypair is even by checking the public key's parity and negating if odd.
pub fn even_kp((sk, pk): (SecretKey, PublicKey)) -> (EvenSecretKey, EvenPublicKey) {
    match (sk, pk) {
        (sk, pk) if pk.x_only_public_key().1 == Parity::Odd => (
            EvenSecretKey(sk.negate()),
            EvenPublicKey(pk.negate(SECP256K1)),
        ),
        (sk, pk) => (EvenSecretKey(sk), EvenPublicKey(pk)),
    }
}
