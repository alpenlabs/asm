use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::AdminTxType;

use super::{IndentedDetails, RenderSigningMessage, UpdateAction};
use crate::actions::UpdateId;

#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct CancelAction {
    /// ID of the update that needs to be cancelled.
    target_id: UpdateId,
    /// The update being cancelled. Embedded so the signing message describes the full
    /// payload signers are authorizing the cancellation of, and so role resolution can
    /// proceed without consulting the queue.
    update: UpdateAction,
}

impl CancelAction {
    pub fn new(target_id: UpdateId, update: UpdateAction) -> Self {
        CancelAction { target_id, update }
    }

    pub fn target_id(&self) -> &UpdateId {
        &self.target_id
    }

    pub fn update(&self) -> &UpdateAction {
        &self.update
    }
}

impl RenderSigningMessage for CancelAction {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Cancel
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        details.push(format!("Target Id: {}", self.target_id));
        self.update.render_details(details);
    }
}
