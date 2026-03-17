use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use strata_predicate::{PredicateKey, PredicateKeyBuf};

use crate::{actions::Sighash, constants::AdminTxType};

/// An update to the verifying key for a given Strata proof layer.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Serialize, Deserialize)]
pub struct PredicateUpdate {
    key_bytes: Vec<u8>,
    kind: ProofType,
}

impl PredicateUpdate {
    /// Create a new `VerifyingKeyUpdate`.
    pub fn new(key: PredicateKey, kind: ProofType) -> Self {
        Self {
            key_bytes: key.as_buf_ref().to_bytes(),
            kind,
        }
    }

    /// Borrow the updated verifying key.
    pub fn key(&self) -> PredicateKey {
        PredicateKeyBuf::try_from(self.key_bytes.as_slice())
            .expect("predicate update key bytes should remain valid")
            .to_owned()
    }

    /// Get the associated proof kind.
    pub fn kind(&self) -> ProofType {
        self.kind
    }

    /// Consume and return the inner values.
    pub fn into_inner(self) -> (PredicateKey, ProofType) {
        (
            PredicateKeyBuf::try_from(self.key_bytes.as_slice())
                .expect("predicate update key bytes should remain valid")
                .to_owned(),
            self.kind,
        )
    }
}

impl Sighash for PredicateUpdate {
    fn tx_type(&self) -> AdminTxType {
        match self.kind {
            ProofType::Asm => AdminTxType::AsmStfVkUpdate,
            ProofType::OLStf => AdminTxType::OlStfVkUpdate,
        }
    }

    /// Returns the raw bytes of the [`PredicateKey`].
    ///
    /// Only the key is included because the proof kind is already covered by
    /// the [`AdminTxType`] returned from [`tx_type`](Self::tx_type).
    fn sighash_payload(&self) -> Vec<u8> {
        self.key_bytes.clone()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Arbitrary, Serialize, Deserialize)]
pub enum ProofType {
    Asm,
    OLStf,
}
