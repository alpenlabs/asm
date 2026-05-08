use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};
use strata_crypto::EvenPublicKey;
use strata_identifiers::Buf32;

use crate::actions::{
    IndentedDetails, RenderSigningMessage, updates::render::append_indexed_fields,
};

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

impl RenderSigningMessage for OperatorSetUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::OperatorUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        append_indexed_fields(
            details,
            "Operators to Add",
            "Add Operator",
            self.add_members
                .iter()
                .cloned()
                .map(|member| format!("{:x}", Buf32::from(member))),
        );
        append_indexed_fields(
            details,
            "Operators to Remove",
            "Remove Operator Index",
            self.remove_members.iter().map(u32::to_string),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    /// secp256k1 generator G's x-coordinate — a canonical, even-parity x-only public key.
    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    #[test]
    fn renders_signing_message() {
        let pk = EvenPublicKey::try_from(Buf32(GENERATOR_X)).expect("valid x-only key");
        let update = OperatorSetUpdate::new(vec![pk], vec![5]);
        let action = MultisigAction::Update(UpdateAction::OperatorSet(update));

        let message = SigningMessage::for_action(&action, 9);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: Bridge Operator Set Update\n\
             Authorized By: Strata Administrator\n\
             Sequence: 9\n\
             Action Details:\n  \
             Operators to Add: 1\n  \
             1. Add Operator: 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\n  \
             Operators to Remove: 1\n  \
             1. Remove Operator Index: 5",
        );
    }
}
