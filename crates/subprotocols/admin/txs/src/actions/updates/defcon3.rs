use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, UpdateTxType};

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// Defcon 3 delayed sweep authorization.
///
/// Authorized by the
/// [`Role::StrataSecurityCouncil`](strata_asm_params::Role::StrataSecurityCouncil) to signal the
/// bridge to activate its safe harbour after the timelock configured in
/// [`ConfirmationDepths::defcon3`](strata_asm_params::ConfirmationDepths). Carries no payload.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct Defcon3Update;

impl RenderSigningMessage for Defcon3Update {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Update(UpdateTxType::Defcon3)
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
    fn defcon3_renders_signing_message() {
        let action = MultisigAction::Update(UpdateAction::Defcon3(Defcon3Update));

        let message = SigningMessage::for_action(&action, 42);
        assert_eq!(
            message.as_str(),
            "Strata ASM Administration v1\n\
             Action: Defcon 3\n\
             Authorized By: Strata Security Council\n\
             Sequence: 42",
        );
    }
}
