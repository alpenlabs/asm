use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_crypto::EvenPublicKey;

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
