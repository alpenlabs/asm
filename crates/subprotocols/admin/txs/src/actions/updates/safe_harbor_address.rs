use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_admin_types::{AdminTxType, UpdateTxType};
use strata_asm_bridge_types::SafeHarborAddress;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// Rotate the bridge's safe harbor destination address.
///
/// Authorized by the
/// [`Role::StrataAdministrator`](strata_asm_admin_types::Role::StrataAdministrator) — the
/// security council can sweep funds to the safe harbor via Defcon signals but must not
/// also choose where they land, otherwise the same authority could both trigger a sweep
/// and pick its destination. Carries the new P2TR destination that the bridge will adopt;
/// activation state of the safe harbor is unaffected (only Defcon signals toggle
/// activation).
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct SafeHarborAddressUpdate {
    address: SafeHarborAddress,
}

impl SafeHarborAddressUpdate {
    /// Create a new `SafeHarborAddressUpdate` for the given P2TR address.
    pub fn new(address: SafeHarborAddress) -> Self {
        Self { address }
    }

    /// Borrow the new safe harbor address.
    pub fn address(&self) -> &SafeHarborAddress {
        &self.address
    }

    /// Consume and return the inner safe harbor address.
    pub fn into_inner(self) -> SafeHarborAddress {
        self.address
    }
}

impl RenderSigningMessage for SafeHarborAddressUpdate {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::SafeHarborAddressUpdate)
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        details.push(format!(
            "New Safe Harbor Address: {}",
            hex::encode(self.address.as_descriptor().to_bytes())
        ));
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use bitcoin_bosd::Descriptor;

    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn renders_signing_message() {
        // x-only public key for the generator point G.
        let payload = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        let descriptor = Descriptor::new_p2tr(&payload).expect("valid x-only public key");
        let expected_hex = hex::encode(descriptor.to_bytes());
        let address = SafeHarborAddress::try_from(descriptor).expect("p2tr descriptor accepted");
        let update = SafeHarborAddressUpdate::new(address);
        let action = MultisigAction::Update(UpdateAction::SafeHarborAddress(update));

        let message = SigningMessage::for_action(&action, 17, Network::Regtest);
        assert_eq!(
            message.as_str(),
            format!(
                "Strata ASM Administration v1\n\
                 Network: regtest\n\
                 Action: Safe Harbor Address Update\n\
                 Authorized By: Strata Administrator\n\
                 Sequence: 17\n\
                 Action Details:\n  \
                 New Safe Harbor Address: {expected_hex}"
            )
        );
    }
}
