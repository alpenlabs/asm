use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::AdminTxType;

use super::Sighash;
use crate::actions::UpdateId;

#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
pub struct CancelAction {
    /// ID of the update that needs to be cancelled.
    target_id: UpdateId,
}

impl CancelAction {
    pub fn new(id: UpdateId) -> Self {
        CancelAction { target_id: id }
    }

    pub fn target_id(&self) -> &UpdateId {
        &self.target_id
    }
}

impl Sighash for CancelAction {
    fn tx_type(&self) -> AdminTxType {
        AdminTxType::Cancel
    }

    fn sighash_payload(&self) -> Vec<u8> {
        self.target_id.to_be_bytes().to_vec()
    }
}
