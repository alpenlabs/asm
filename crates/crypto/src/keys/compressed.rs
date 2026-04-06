use std::ops::Deref;

use secp256k1::{Error, PublicKey};

/// A compressed secp256k1 public key (33 bytes).
///
/// This is a thin wrapper around `secp256k1::PublicKey` that adds Borsh
/// serialization support. Unlike `EvenPublicKey`, this type does not
/// enforce even parity - it accepts any valid compressed public key.
///
/// **Why no parity enforcement?** This key is used for ECDSA signature
/// verification (not Schnorr/BIP340). ECDSA signatures work with both
/// even and odd parity keys, unlike Schnorr which requires even parity
/// for x-only public keys.
///
/// Serializes the key as a 33-byte compressed point where the first byte
/// indicates the y-coordinate parity (0x02 for even, 0x03 for odd).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedPublicKey(PublicKey);

impl CompressedPublicKey {
    /// Create a new `CompressedPublicKey` from a byte slice.
    ///
    /// The slice must be exactly 33 bytes in compressed format (0x02 or 0x03 prefix).
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_slice(data)?;
        Ok(Self(pk))
    }

    /// Get the inner `secp256k1::PublicKey`.
    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }

    /// Serialize to 33-byte compressed format.
    ///
    /// Serializes the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    pub fn serialize(&self) -> [u8; 33] {
        self.0.serialize()
    }
}

impl Deref for CompressedPublicKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<PublicKey> for CompressedPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl From<PublicKey> for CompressedPublicKey {
    fn from(pk: PublicKey) -> Self {
        Self(pk)
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(pk: CompressedPublicKey) -> Self {
        pk.0
    }
}
