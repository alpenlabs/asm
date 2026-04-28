pub mod operator;
pub mod seq;

use arbitrary::Arbitrary;
use ssz_derive::{Decode, Encode};
use strata_asm_params::{Role, UpdateTxType};
use strata_crypto::threshold_signature::ThresholdConfigUpdate;
use strata_predicate::PredicateKey;

use crate::actions::updates::{operator::OperatorSetUpdate, seq::SequencerUpdate};

/// An action that updates some part of the ASM.
///
/// One variant per [`UpdateTxType`]: the wire-format tx type, the variant identity,
/// and the [`crate::actions::sighash::Sighash`] are all in lockstep, so adding a new
/// admin update kind forces matching arms across all dispatch sites.
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
        match self {
            UpdateAction::StrataAdminMultisig(_) => Role::StrataAdministrator,
            UpdateAction::StrataSeqManagerMultisig(_) => Role::StrataSequencerManager,
            UpdateAction::AlpenAdminMultisig(_) => Role::AlpenAdministrator,
            UpdateAction::OperatorSet(_) => Role::StrataAdministrator,
            UpdateAction::Sequencer(_) => Role::StrataSequencerManager,
            UpdateAction::OlStfVk(_) | UpdateAction::AsmStfVk(_) => Role::StrataAdministrator,
            UpdateAction::EeStfVk(_) => Role::AlpenAdministrator,
        }
    }

    /// The action-specific bytes contributed to the sighash.
    ///
    /// The variant identity is conveyed by the surrounding [`crate::actions::sighash::Sighash`]
    /// `tx_type` so it is not repeated in the payload.
    pub fn sighash_payload(&self) -> Vec<u8> {
        match self {
            UpdateAction::StrataAdminMultisig(config)
            | UpdateAction::StrataSeqManagerMultisig(config)
            | UpdateAction::AlpenAdminMultisig(config) => threshold_config_update_payload(config),
            UpdateAction::OperatorSet(o) => o.sighash_payload(),
            UpdateAction::Sequencer(s) => s.sighash_payload(),
            UpdateAction::OlStfVk(k) | UpdateAction::AsmStfVk(k) | UpdateAction::EeStfVk(k) => {
                k.as_buf_ref().to_bytes()
            }
        }
    }
}

/// Returns `len(add) ‖ add[0] ‖ … ‖ add[n] ‖ len(rem) ‖ rem[0] ‖ … ‖ rem[m] ‖ threshold`,
/// where lengths are big-endian `u32` and members are 33-byte compressed public keys.
fn threshold_config_update_payload(config: &ThresholdConfigUpdate) -> Vec<u8> {
    let add = config.add_members();
    let rem = config.remove_members();
    let mut buf = Vec::with_capacity(4 + add.len() * 33 + 4 + rem.len() * 33 + 1);
    buf.extend_from_slice(&(add.len() as u32).to_be_bytes());
    for member in add {
        buf.extend_from_slice(&member.serialize());
    }
    buf.extend_from_slice(&(rem.len() as u32).to_be_bytes());
    for member in rem {
        buf.extend_from_slice(&member.serialize());
    }
    buf.push(config.new_threshold().get());
    buf
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
