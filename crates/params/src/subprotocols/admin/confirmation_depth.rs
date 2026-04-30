#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};

use crate::UpdateTxType;

/// Per-variant confirmation depths (CD) for admin updates, in Bitcoin blocks.
///
/// After an update transaction receives this many confirmations, the update is enacted
/// automatically. During this confirmation period, the update can still be cancelled by
/// submitting a cancel transaction. A field value of `0` is a sentinel for "apply
/// immediately" — such updates bypass the queue entirely and surface from [`Self::get`]
/// as `None`.
///
/// Design choice: individual named fields rather than a `HashMap<UpdateTxType, u16>` give
/// compile-time completeness — adding a new [`UpdateTxType`] variant forces a matching
/// field here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ConfirmationDepths {
    pub strata_admin_multisig_update: u16,
    pub strata_seq_manager_multisig_update: u16,
    pub alpen_admin_multisig_update: u16,
    pub operator_update: u16,
    pub sequencer_update: u16,
    pub ol_stf_vk_update: u16,
    pub asm_stf_vk_update: u16,
    pub ee_stf_vk_update: u16,
}

impl ConfirmationDepths {
    /// Returns the confirmation depth configured for `tx_type`, or `None` if the update
    /// is configured to bypass the queue and apply immediately (depth `0`).
    pub fn get(&self, tx_type: UpdateTxType) -> Option<u16> {
        let depth = match tx_type {
            UpdateTxType::StrataAdminMultisigUpdate => self.strata_admin_multisig_update,
            UpdateTxType::StrataSeqManagerMultisigUpdate => self.strata_seq_manager_multisig_update,
            UpdateTxType::AlpenAdminMultisigUpdate => self.alpen_admin_multisig_update,
            UpdateTxType::OperatorUpdate => self.operator_update,
            UpdateTxType::SequencerUpdate => self.sequencer_update,
            UpdateTxType::OlStfVkUpdate => self.ol_stf_vk_update,
            UpdateTxType::AsmStfVkUpdate => self.asm_stf_vk_update,
            UpdateTxType::EeStfVkUpdate => self.ee_stf_vk_update,
        };
        (depth != 0).then_some(depth)
    }
}
