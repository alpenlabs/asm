//! Compressed secp256k1 public key used by the administration threshold scheme.

use std::{
    hash::{Hash, Hasher},
    io,
    ops::Deref,
};

use borsh::{BorshDeserialize, BorshSerialize};
use secp256k1::{Error, PublicKey};
use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};

/// Length of a compressed secp256k1 point.
const COMPRESSED_POINT_LEN: usize = 33;

/// A compressed secp256k1 public key (33 bytes).
///
/// Unlike an x-only key, this type does not enforce even parity. Administration actions are
/// authorized with ECDSA rather than Schnorr, and ECDSA verification works with either
/// parity, so constraining it would only reject keys a hardware wallet can legitimately
/// produce.
///
/// The key is serialized as a 33-byte compressed point whose first byte encodes the
/// y-coordinate parity (`0x02` even, `0x03` odd).
// TODO: this duplicates `strata_crypto::keys::compressed::CompressedPublicKey`. The copy
// exists because `ThresholdConfig` needs `Hash` to dedup signer rosters, and the orphan rule
// forbids implementing it for a foreign type from here. Upstream the `Hash` impl to
// strata-crypto and collapse the two types back into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedPublicKey(PublicKey);

impl CompressedPublicKey {
    /// Creates a key from a byte slice, which must be exactly 33 bytes of compressed point.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(Self(PublicKey::from_slice(data)?))
    }

    /// Returns the inner [`PublicKey`].
    pub fn as_inner(&self) -> &PublicKey {
        &self.0
    }

    /// Returns the 33-byte compressed encoding.
    pub fn serialize(&self) -> [u8; COMPRESSED_POINT_LEN] {
        self.0.serialize()
    }
}

/// Hashing by the compressed encoding lets rosters be deduplicated with a set. `PublicKey`
/// itself is not `Hash`, which is why this type exists separately from the strata-crypto one.
impl Hash for CompressedPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize().hash(state);
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

// Byte layout: the raw 33-byte compressed point, with no length prefix.
impl Encode for CompressedPublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        COMPRESSED_POINT_LEN
    }

    fn ssz_bytes_len(&self) -> usize {
        COMPRESSED_POINT_LEN
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.serialize());
    }
}

impl Decode for CompressedPublicKey {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        COMPRESSED_POINT_LEN
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != COMPRESSED_POINT_LEN {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: COMPRESSED_POINT_LEN,
            });
        }
        // Rejects anything that is not a curve point, so a decoded key is always usable.
        Self::from_slice(bytes).map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl BorshSerialize for CompressedPublicKey {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.serialize())
    }
}

impl BorshDeserialize for CompressedPublicKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; COMPRESSED_POINT_LEN];
        reader.read_exact(&mut buf)?;
        Self::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Serialize for CompressedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.serialize()))
    }
}

impl<'de> Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as DeError;

        let hex_string: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(DeError::custom)?;
        Self::from_slice(&bytes).map_err(DeError::custom)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for CompressedPublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use secp256k1::{SECP256K1, SecretKey};

        let mut sk_bytes = [0u8; 32];
        u.fill_buffer(&mut sk_bytes)?;
        // A zero scalar is not a valid secret key, so nudge it into range.
        if sk_bytes.iter().all(|&b| b == 0) {
            sk_bytes[31] = 1;
        }
        let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(Self(PublicKey::from_secret_key(SECP256K1, &sk)))
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{SECP256K1, SecretKey};

    use super::*;

    fn test_key(seed: u8) -> CompressedPublicKey {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("seed is a valid scalar");
        CompressedPublicKey::from(PublicKey::from_secret_key(SECP256K1, &sk))
    }

    #[test]
    fn serialize_roundtrips_through_from_slice() {
        let key = test_key(1);
        assert_eq!(CompressedPublicKey::from_slice(&key.serialize()), Ok(key));
    }

    #[test]
    fn borsh_roundtrips() {
        let key = test_key(2);
        let encoded = borsh::to_vec(&key).unwrap();
        assert_eq!(encoded.len(), COMPRESSED_POINT_LEN);
        assert_eq!(
            borsh::from_slice::<CompressedPublicKey>(&encoded).unwrap(),
            key
        );
    }

    #[test]
    fn ssz_encodes_as_the_bare_compressed_point() {
        let key = test_key(3);
        let encoded = key.as_ssz_bytes();
        assert_eq!(encoded, key.serialize().to_vec());
        assert_eq!(CompressedPublicKey::from_ssz_bytes(&encoded), Ok(key));
    }

    #[test]
    fn ssz_rejects_wrong_length_and_non_curve_points() {
        assert!(CompressedPublicKey::from_ssz_bytes(&[0u8; 32]).is_err());
        assert!(CompressedPublicKey::from_ssz_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn serde_roundtrips_as_hex() {
        let key = test_key(4);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(json, format!("\"{}\"", hex::encode(key.serialize())));
        assert_eq!(
            serde_json::from_str::<CompressedPublicKey>(&json).unwrap(),
            key
        );
    }

    #[test]
    fn equal_keys_hash_equally() {
        use std::collections::HashSet;

        let keys: HashSet<_> = [test_key(5), test_key(5), test_key(6)]
            .into_iter()
            .collect();
        assert_eq!(keys.len(), 2);
    }
}
