//! Error types for threshold signature operations.

use thiserror::Error;

/// Errors that can occur during threshold signature operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ThresholdSignatureError {
    /// Not enough signatures to meet the threshold.
    #[error("insufficient signatures: provided {provided}, required {required}")]
    InsufficientSignatures {
        /// Number of signatures provided.
        provided: usize,
        /// Number of signatures required.
        required: usize,
    },

    /// Invalid public key data.
    #[error("invalid public key{}: {reason}", index.map(|i| format!(" at index {}", i)).unwrap_or_default())]
    InvalidPublicKey {
        /// Optional index of the invalid key.
        index: Option<usize>,
        /// Description of why the key is invalid.
        reason: String,
    },

    /// Invalid threshold value.
    #[error("invalid threshold: {threshold} exceeds total keys {total_keys}")]
    InvalidThreshold {
        /// Requested threshold value.
        threshold: u8,
        /// Total number of keys in the set.
        total_keys: usize,
    },

    /// Signature verification failed for the given signer index.
    #[error("invalid signature at index {index}")]
    InvalidSignature {
        /// Signer index whose signature failed verification.
        index: u8,
    },

    /// Invalid signature format.
    #[error("invalid signature format")]
    InvalidSignatureFormat,

    /// Duplicate signer index in signature set.
    #[error("duplicate signer index: {0}")]
    DuplicateSignerIndex(u8),

    /// Signer index out of bounds.
    #[error("signer index {index} out of bounds (max: {max})")]
    SignerIndexOutOfBounds {
        /// The out-of-bounds signer index.
        index: u8,
        /// Maximum valid index.
        max: usize,
    },

    /// Member already exists in the configuration.
    #[error("member already exists")]
    MemberAlreadyExists,

    /// Duplicate member in add list.
    #[error("duplicate member in add list")]
    DuplicateAddMember,

    /// Duplicate member in remove list.
    #[error("duplicate member in remove list")]
    DuplicateRemoveMember,

    /// Member not found in the configuration.
    #[error("member not found")]
    MemberNotFound,

    /// Invalid message hash.
    #[error("invalid message hash")]
    InvalidMessageHash,

    /// The configuration would exceed the maximum number of signers.
    #[error("too many signers (count {count}, max {max})")]
    TooManySigners {
        /// Number of signers the configuration would hold.
        count: usize,
        /// Maximum number of signers allowed ([`MAX_SIGNERS`](crate::MAX_SIGNERS)).
        max: usize,
    },
}

impl From<secp256k1::Error> for ThresholdSignatureError {
    fn from(e: secp256k1::Error) -> Self {
        Self::InvalidPublicKey {
            index: None,
            reason: e.to_string(),
        }
    }
}
