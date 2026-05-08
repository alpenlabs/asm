use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{AdminTxType, Role};
use strata_l1_txfmt::TagData;

mod cancel;
mod sighash;
pub mod updates;

pub use cancel::CancelAction;
pub(crate) use sighash::{IndentedDetails, RenderSigningMessage};
pub use updates::UpdateAction;

use crate::constants::ADMINISTRATION_SUBPROTOCOL_ID;

pub type UpdateId = u32;

/// A high‐level multisig operation that participants can propose.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum MultisigAction {
    /// Cancel a pending action.
    Cancel(CancelAction),
    /// Propose an update.
    Update(UpdateAction),
}

impl RenderSigningMessage for MultisigAction {
    fn tx_type(&self) -> AdminTxType {
        match self {
            MultisigAction::Cancel(c) => c.tx_type(),
            MultisigAction::Update(u) => u.tx_type(),
        }
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        match self {
            MultisigAction::Cancel(c) => c.render_details(details),
            MultisigAction::Update(u) => u.render_details(details),
        }
    }
}

impl MultisigAction {
    /// Constructs the SPS-50 [`TagData`] for this action.
    ///
    /// The tag is built from the administration subprotocol ID and the
    /// action's [`AdminTxType`], with no auxiliary data.
    pub fn tag(&self) -> TagData {
        TagData::new(ADMINISTRATION_SUBPROTOCOL_ID, self.tx_type().into(), vec![])
            .expect("empty aux data always fits")
    }

    /// The role authorized to enact this action.
    ///
    /// Both variants are self-describing: an update carries its type directly, and a cancel
    /// embeds the [`UpdateAction`] it targets — so the role is derivable without external
    /// context (queue lookup, authority registry).
    pub fn required_role(&self) -> Role {
        match self {
            MultisigAction::Update(update) => update.required_role(),
            MultisigAction::Cancel(cancel) => cancel.update().required_role(),
        }
    }
}
