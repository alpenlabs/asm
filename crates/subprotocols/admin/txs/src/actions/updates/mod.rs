pub mod operator;
pub mod seq;

use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{Role, UpdateTxType};
use strata_crypto::{hash, threshold_signature::ThresholdConfigUpdate};
use strata_identifiers::Buf32;
use strata_predicate::{PredicateKey, PredicateTypeId};

use crate::{
    actions::updates::{operator::OperatorSetUpdate, seq::SequencerUpdate},
    signing_message::{append_indexed_fields, role_label},
};

/// An action that updates some part of the ASM.
///
/// One variant per [`UpdateTxType`]: the wire-format tx type, the variant identity,
/// and the [`crate::actions::sighash::SigningMessage`] are all in lockstep, so adding a
/// new admin update kind forces matching arms across all dispatch sites.
#[derive(Clone, Debug, Eq, PartialEq, Arbitrary, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum UpdateAction {
    StrataAdminMultisig(ThresholdConfigUpdate),
    StrataSeqManagerMultisig(ThresholdConfigUpdate),
    AlpenAdminMultisig(ThresholdConfigUpdate),
    OperatorSet(OperatorSetUpdate),
    Sequencer(SequencerUpdate),
    OlStfVk(PredicateKey),
    AsmStfVk(PredicateKey),
    EeStfVk(PredicateKey),
}

impl UpdateAction {
    /// The narrow [`UpdateTxType`] this action represents.
    pub fn tx_type(&self) -> UpdateTxType {
        match self {
            UpdateAction::StrataAdminMultisig(_) => UpdateTxType::StrataAdminMultisigUpdate,
            UpdateAction::StrataSeqManagerMultisig(_) => {
                UpdateTxType::StrataSeqManagerMultisigUpdate
            }
            UpdateAction::AlpenAdminMultisig(_) => UpdateTxType::AlpenAdminMultisigUpdate,
            UpdateAction::OperatorSet(_) => UpdateTxType::OperatorUpdate,
            UpdateAction::Sequencer(_) => UpdateTxType::SequencerUpdate,
            UpdateAction::OlStfVk(_) => UpdateTxType::OlStfVkUpdate,
            UpdateAction::AsmStfVk(_) => UpdateTxType::AsmStfVkUpdate,
            UpdateAction::EeStfVk(_) => UpdateTxType::EeStfVkUpdate,
        }
    }

    /// The role authorized to enact this update.
    pub fn required_role(&self) -> Role {
        self.tx_type().authorized_role()
    }

    /// Pushes the action-specific signing message lines for this update.
    pub fn render_details(&self, lines: &mut Vec<String>) {
        match self {
            UpdateAction::StrataAdminMultisig(config) => {
                render_multisig_update_details(Role::StrataAdministrator, config, lines)
            }
            UpdateAction::StrataSeqManagerMultisig(config) => {
                render_multisig_update_details(Role::StrataSequencerManager, config, lines)
            }
            UpdateAction::AlpenAdminMultisig(config) => {
                render_multisig_update_details(Role::AlpenAdministrator, config, lines)
            }
            UpdateAction::OperatorSet(update) => render_operator_update_details(update, lines),
            UpdateAction::Sequencer(update) => render_sequencer_update_details(update, lines),
            UpdateAction::OlStfVk(key) => render_predicate_update_details("OLStf", key, lines),
            UpdateAction::AsmStfVk(key) => render_predicate_update_details("Asm", key, lines),
            UpdateAction::EeStfVk(key) => render_predicate_update_details("EeStf", key, lines),
        }
    }
}

fn render_multisig_update_details(
    role: Role,
    config: &ThresholdConfigUpdate,
    lines: &mut Vec<String>,
) {
    lines.push(format!("target_role: {}", role_label(role)));
    lines.push(format!("new_threshold: {}", config.new_threshold()));
    append_indexed_fields(
        lines,
        "add_member",
        config
            .add_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
    append_indexed_fields(
        lines,
        "remove_member",
        config
            .remove_members()
            .iter()
            .map(|member| hex::encode(member.serialize())),
    );
}

fn render_operator_update_details(update: &OperatorSetUpdate, lines: &mut Vec<String>) {
    append_indexed_fields(
        lines,
        "add_member",
        update
            .add_members()
            .iter()
            .cloned()
            .map(|member| format!("{:x}", Buf32::from(member))),
    );
    append_indexed_fields(
        lines,
        "remove_member",
        update.remove_members().iter().map(u32::to_string),
    );
}

fn render_sequencer_update_details(update: &SequencerUpdate, lines: &mut Vec<String>) {
    lines.push(format!("new_sequencer_key: {:x}", update.pub_key()));
}

fn render_predicate_update_details(
    proof_type_label: &str,
    key: &PredicateKey,
    lines: &mut Vec<String>,
) {
    let predicate_type = PredicateTypeId::try_from(key.id())
        .expect("predicate type should be validated at construction");
    let condition = key.condition();
    lines.push(format!("proof_type: {proof_type_label}"));
    lines.push(format!("predicate_type: {predicate_type}"));
    lines.push(format!("condition_len: {}", condition.len()));
    if condition.len() <= 32 {
        lines.push(format!("condition_hex: {}", hex::encode(condition)));
    } else {
        lines.push(format!("condition_hash: {:x}", hash::raw(condition)));
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
