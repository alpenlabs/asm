//! Stable identity of a qualified guest artifact.
//!
//! The identity is a SHA-256 digest of the canonical artifact statement in a
//! release manifest. It is deliberately a fixed-width value: proof-job records
//! can persist it without depending on a filesystem path or a mutable operator
//! label.

use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Content identity of one qualified guest artifact.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct GuestArtifactId([u8; 32]);

/// ASM-specific name for a guest artifact identity.
///
/// Moho artifacts use the same digest representation, while durable ASM proof
/// jobs use this alias to make the domain explicit at call sites.
pub type AsmArtifactId = GuestArtifactId;

impl GuestArtifactId {
    /// Constructs an identity from its SHA-256 digest bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the identity and returns its digest bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for GuestArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for GuestArtifactId {
    type Err = ParseGuestArtifactIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = value.strip_prefix("sha256:").unwrap_or(value);
        let decoded = hex::decode(hex).map_err(ParseGuestArtifactIdError::InvalidHex)?;
        let bytes = decoded
            .try_into()
            .map_err(|bytes: Vec<u8>| ParseGuestArtifactIdError::InvalidLength(bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl Serialize for GuestArtifactId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for GuestArtifactId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <String as Deserialize>::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

/// A guest artifact identity was not a 32-byte SHA-256 digest.
#[derive(Debug, thiserror::Error)]
pub enum ParseGuestArtifactIdError {
    /// The digest was not hexadecimal.
    #[error("artifact id is not valid hexadecimal")]
    InvalidHex(#[source] hex::FromHexError),

    /// The decoded digest did not contain exactly 32 bytes.
    #[error("artifact id contains {0} bytes; expected 32")]
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_serde_use_a_domain_labeled_digest() {
        let id = GuestArtifactId::new([0xab; 32]);
        let expected = format!("sha256:{}", "ab".repeat(32));

        assert_eq!(id.to_string(), expected);
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{expected}\"")
        );
        assert_eq!(
            serde_json::from_str::<GuestArtifactId>(&format!("\"{expected}\"")).unwrap(),
            id
        );
        assert_eq!(expected.parse::<GuestArtifactId>().unwrap(), id);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(matches!(
            "sha256:abcd".parse::<GuestArtifactId>(),
            Err(ParseGuestArtifactIdError::InvalidLength(2))
        ));
    }
}
