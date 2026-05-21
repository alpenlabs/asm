use arbitrary::Arbitrary;
use bitcoin_bosd::Descriptor;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// Rotate the bridge's safe harbour destination address.
///
/// Authorized by the
/// [`Role::StrataSecurityCouncil`](strata_asm_params::Role::StrataSecurityCouncil). Carries the
/// new destination descriptor that the bridge will adopt; activation state of the safe
/// harbour is unaffected (only Defcon signals toggle activation).
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct SafeHarbourAddressUpdate {
    address: Descriptor,
}

impl SafeHarbourAddressUpdate {
    /// Create a new `SafeHarbourAddressUpdate` for the given descriptor.
    pub fn new(address: Descriptor) -> Self {
        Self { address }
    }

    /// Borrow the new safe harbour address.
    pub fn address(&self) -> &Descriptor {
        &self.address
    }

    /// Consume and return the inner descriptor.
    pub fn into_inner(self) -> Descriptor {
        self.address
    }
}

impl RenderSigningMessage for SafeHarbourAddressUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::SafeHarbourAddressUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        details.push(format!(
            "New Safe Harbour Address: {}",
            hex::encode(self.address.to_bytes())
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn renders_signing_message() {
        let descriptor = Descriptor::new_p2wpkh(&[0xAB; 20]);
        let expected_hex = hex::encode(descriptor.to_bytes());
        let update = SafeHarbourAddressUpdate::new(descriptor);
        let action = MultisigAction::Update(UpdateAction::SafeHarbourAddress(update));

        let message = SigningMessage::for_action(&action, 17);
        assert_eq!(
            message.as_str(),
            format!(
                "Strata ASM Administration v1\n\
                 Action: Safe Harbour Address Update\n\
                 Authorized By: Strata Security Council\n\
                 Sequence: 17\n\
                 Action Details:\n  \
                 New Safe Harbour Address: {expected_hex}"
            )
        );
    }
}
