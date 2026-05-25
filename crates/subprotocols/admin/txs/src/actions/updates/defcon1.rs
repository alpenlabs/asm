use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// Defcon 1 immediate sweep authorization.
///
/// Authorized by the
/// [`Role::StrataSecurityCouncil`](strata_asm_params::Role::StrataSecurityCouncil) to signal the
/// bridge to immediately activate its safe harbour. Carries no payload: the action's identity is
/// the signal. Defcon 1 is enacted immediately on receipt — by definition the emergency lever
/// bypasses the confirmation queue, so it has no entry in
/// [`ConfirmationDepths`](strata_asm_params::ConfirmationDepths) and cannot be cancelled.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct Defcon1Update;

impl RenderSigningMessage for Defcon1Update {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::Defcon1)
    }

    fn render_details(&self, _details: &mut IndentedDetails<'_>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actions::{MultisigAction, UpdateAction},
        signing_message::SigningMessage,
    };

    #[test]
    fn defcon1_renders_signing_message() {
        let action = MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update));

        let message = SigningMessage::for_action(&action, 42);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: Defcon 1\n\
             Authorized By: Strata Security Council\n\
             Sequence: 42",
        );
    }
}
