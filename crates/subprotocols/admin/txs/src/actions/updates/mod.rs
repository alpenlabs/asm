pub mod alpen_admin_multisig;
pub mod asm_stf_vk;
pub mod defcon1;
pub mod defcon3;
pub mod ee_stf_vk;
pub mod ol_stf_vk;
pub mod operator_set;
pub mod safe_harbour_address;
pub mod strata_admin_multisig;
pub mod strata_security_council_multisig;
pub mod strata_seq_manager_multisig;
pub mod strata_sequencer;

mod render;

pub use alpen_admin_multisig::AlpenAdminMultisigUpdate;
use arbitrary::Arbitrary;
pub use asm_stf_vk::AsmStfVkUpdate;
pub use defcon1::Defcon1Update;
pub use defcon3::Defcon3Update;
pub use ee_stf_vk::EeStfVkUpdate;
pub use ol_stf_vk::OlStfVkUpdate;
pub use operator_set::OperatorSetUpdate;
pub use safe_harbour_address::SafeHarbourAddressUpdate;
use ssz_derive::{Decode, Encode};
pub use strata_admin_multisig::StrataAdminMultisigUpdate;
use strata_asm_params::{AdminTxType, Role, UpdateTxType};
pub use strata_security_council_multisig::StrataSecurityCouncilMultisigUpdate;
pub use strata_seq_manager_multisig::StrataSeqManagerMultisigUpdate;
pub use strata_sequencer::SequencerUpdate;

use crate::actions::{IndentedDetails, RenderSigningMessage};

/// An action that updates some part of the ASM.
///
/// One variant per [`UpdateTxType`]: the wire-format tx type, the variant identity,
/// and the per-variant `RenderSigningMessage` impl are all in lockstep, so adding a new
/// admin update kind forces matching arms across all dispatch sites.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum UpdateAction {
    StrataAdminMultisig(StrataAdminMultisigUpdate),
    StrataSeqManagerMultisig(StrataSeqManagerMultisigUpdate),
    AlpenAdminMultisig(AlpenAdminMultisigUpdate),
    StrataSecurityCouncilMultisig(StrataSecurityCouncilMultisigUpdate),
    OperatorSet(OperatorSetUpdate),
    Sequencer(SequencerUpdate),
    OlStfVk(OlStfVkUpdate),
    AsmStfVk(AsmStfVkUpdate),
    EeStfVk(EeStfVkUpdate),
    Defcon1(Defcon1Update),
    Defcon3(Defcon3Update),
    SafeHarbourAddress(SafeHarbourAddressUpdate),
}

impl UpdateAction {
    /// The narrow [`UpdateTxType`] this action represents.
    pub fn update_tx_type(&self) -> UpdateTxType {
        match self {
            UpdateAction::StrataAdminMultisig(_) => UpdateTxType::StrataAdminMultisigUpdate,
            UpdateAction::StrataSeqManagerMultisig(_) => {
                UpdateTxType::StrataSeqManagerMultisigUpdate
            }
            UpdateAction::AlpenAdminMultisig(_) => UpdateTxType::AlpenAdminMultisigUpdate,
            UpdateAction::StrataSecurityCouncilMultisig(_) => {
                UpdateTxType::StrataSecurityCouncilMultisigUpdate
            }
            UpdateAction::OperatorSet(_) => UpdateTxType::OperatorUpdate,
            UpdateAction::Sequencer(_) => UpdateTxType::SequencerUpdate,
            UpdateAction::OlStfVk(_) => UpdateTxType::OlStfVkUpdate,
            UpdateAction::AsmStfVk(_) => UpdateTxType::AsmStfVkUpdate,
            UpdateAction::EeStfVk(_) => UpdateTxType::EeStfVkUpdate,
            UpdateAction::Defcon1(_) => UpdateTxType::Defcon1,
            UpdateAction::Defcon3(_) => UpdateTxType::Defcon3,
            UpdateAction::SafeHarbourAddress(_) => UpdateTxType::SafeHarbourAddressUpdate,
        }
    }

    /// The role authorized to enact this update.
    pub fn required_role(&self) -> Role {
        self.update_tx_type().authorized_role()
    }
}

impl RenderSigningMessage for UpdateAction {
    fn tx_type(&self) -> AdminTxType {
        match self {
            UpdateAction::StrataAdminMultisig(u) => u.tx_type(),
            UpdateAction::StrataSeqManagerMultisig(u) => u.tx_type(),
            UpdateAction::AlpenAdminMultisig(u) => u.tx_type(),
            UpdateAction::StrataSecurityCouncilMultisig(u) => u.tx_type(),
            UpdateAction::OperatorSet(u) => u.tx_type(),
            UpdateAction::Sequencer(u) => u.tx_type(),
            UpdateAction::OlStfVk(u) => u.tx_type(),
            UpdateAction::AsmStfVk(u) => u.tx_type(),
            UpdateAction::EeStfVk(u) => u.tx_type(),
            UpdateAction::Defcon1(u) => u.tx_type(),
            UpdateAction::Defcon3(u) => u.tx_type(),
            UpdateAction::SafeHarbourAddress(u) => u.tx_type(),
        }
    }

    fn render_details(&self, details: &mut IndentedDetails<'_>) {
        match self {
            UpdateAction::StrataAdminMultisig(u) => u.render_details(details),
            UpdateAction::StrataSeqManagerMultisig(u) => u.render_details(details),
            UpdateAction::AlpenAdminMultisig(u) => u.render_details(details),
            UpdateAction::StrataSecurityCouncilMultisig(u) => u.render_details(details),
            UpdateAction::OperatorSet(u) => u.render_details(details),
            UpdateAction::Sequencer(u) => u.render_details(details),
            UpdateAction::OlStfVk(u) => u.render_details(details),
            UpdateAction::AsmStfVk(u) => u.render_details(details),
            UpdateAction::EeStfVk(u) => u.render_details(details),
            UpdateAction::Defcon1(u) => u.render_details(details),
            UpdateAction::Defcon3(u) => u.render_details(details),
            UpdateAction::SafeHarbourAddress(u) => u.render_details(details),
        }
    }
}

impl From<OperatorSetUpdate> for UpdateAction {
    fn from(update: OperatorSetUpdate) -> Self {
        UpdateAction::OperatorSet(update)
    }
}

impl From<SequencerUpdate> for UpdateAction {
    fn from(update: SequencerUpdate) -> Self {
        UpdateAction::Sequencer(update)
    }
}
