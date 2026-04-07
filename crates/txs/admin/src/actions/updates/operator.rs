use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_crypto::EvenPublicKey;

use crate::{actions::Sighash, constants::AdminTxType};

/// An update to the Bridge Operator Set:
/// - removes the specified `remove_members` (by operator index)
/// - adds the specified `add_members` (by public key)
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct OperatorSetUpdate {
    add_members: Vec<EvenPublicKey>,
    remove_members: Vec<u32>,
}

impl OperatorSetUpdate {
    /// Creates a new `OperatorSetUpdate`.
    pub fn new(add_members: Vec<EvenPublicKey>, remove_members: Vec<u32>) -> Self {
        Self {
            add_members,
            remove_members,
        }
    }

    /// Borrow the list of operator public keys to add.
    pub fn add_members(&self) -> &[EvenPublicKey] {
        &self.add_members
    }

    /// Borrow the list of operator indices to remove.
    pub fn remove_members(&self) -> &[u32] {
        &self.remove_members
    }

    /// Consume and return the inner vectors `(add_members, remove_members)`.
    pub fn into_inner(self) -> (Vec<EvenPublicKey>, Vec<u32>) {
        (self.add_members, self.remove_members)
    }
}

impl Sighash for OperatorSetUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::OperatorUpdate
    }

    /// Returns `len(add) ‖ add[0] ‖ … ‖ add[n] ‖ len(rem) ‖ rem[0] ‖ … ‖ rem[m]`
    /// where lengths are encoded as big-endian `u32`, add members as 32-byte x-only keys,
    /// and remove members as 4-byte big-endian operator indices.
    fn sighash_payload(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(4 + self.add_members.len() * 32 + 4 + self.remove_members.len() * 4);
        buf.extend_from_slice(&(self.add_members.len() as u32).to_be_bytes());
        for member in &self.add_members {
            buf.extend_from_slice(&member.x_only_public_key().0.serialize());
        }
        buf.extend_from_slice(&(self.remove_members.len() as u32).to_be_bytes());
        for member in &self.remove_members {
            buf.extend_from_slice(&member.to_be_bytes());
        }
        buf
    }
}
