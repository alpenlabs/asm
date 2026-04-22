use std::num::NonZero;

use ssz::{Decode, Encode};
use strata_asm_params::Role;
use strata_crypto::threshold_signature::{SignatureSet, ThresholdConfigUpdate};
use strata_l1_txfmt::TagData;

use crate::{
    actions::{
        CancelAction, MultisigAction, UpdateAction,
        updates::{
            multisig::MultisigUpdate,
            operator::OperatorSetUpdate,
            predicate::{PredicateUpdate, ProofType},
            seq::SequencerUpdate,
        },
    },
    constants::AdminTxType,
    errors::AdministrationTxParseError,
    payload::{
        CancelPayload, MultisigUpdatePayload, OperatorUpdatePayload, PredicateUpdatePayload,
        SequencerUpdatePayload,
    },
};

/// A normalized administration action paired with signatures and replay protection state.
///
/// This is the domain-level representation returned by the parser after the tx-type-specific wire
/// payload has been decoded and normalized into the existing admin action model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAction {
    /// Sequence number used to prevent replay attacks and enforce ordering.
    pub seqno: u64,
    /// The administrative action being proposed.
    pub action: MultisigAction,
    /// The set of ECDSA signatures authorizing this action.
    pub signatures: SignatureSet,
}

impl SignedAction {
    /// Creates a new signed administration action.
    pub fn new(seqno: u64, action: MultisigAction, signatures: SignatureSet) -> Self {
        Self {
            seqno,
            action,
            signatures,
        }
    }

    /// Returns the SPS-50 tag for this signed action.
    pub fn tag(&self) -> TagData {
        self.action.tag()
    }

    /// Decodes the witness-envelope payload bytes for the given tx type into a signed action.
    pub fn from_payload_bytes(
        tx_type: AdminTxType,
        bytes: &[u8],
    ) -> Result<Self, AdministrationTxParseError> {
        match tx_type {
            AdminTxType::Cancel => {
                let payload = CancelPayload::from_ssz_bytes(bytes).map_err(|source| {
                    AdministrationTxParseError::MalformedPayload { tx_type, source }
                })?;
                Ok(Self::new(
                    payload.seqno,
                    MultisigAction::Cancel(CancelAction::new(payload.target_id)),
                    payload.signatures,
                ))
            }
            AdminTxType::StrataAdminMultisigUpdate => {
                Self::decode_multisig_update_payload(tx_type, bytes, Role::StrataAdministrator)
            }
            AdminTxType::StrataSeqManagerMultisigUpdate => {
                Self::decode_multisig_update_payload(tx_type, bytes, Role::StrataSequencerManager)
            }
            AdminTxType::OperatorUpdate => {
                let payload = OperatorUpdatePayload::from_ssz_bytes(bytes).map_err(|source| {
                    AdministrationTxParseError::MalformedPayload { tx_type, source }
                })?;
                Ok(Self::new(
                    payload.seqno,
                    MultisigAction::Update(UpdateAction::OperatorSet(OperatorSetUpdate::new(
                        payload.add_members,
                        payload.remove_members,
                    ))),
                    payload.signatures,
                ))
            }
            AdminTxType::SequencerUpdate => {
                let payload = SequencerUpdatePayload::from_ssz_bytes(bytes).map_err(|source| {
                    AdministrationTxParseError::MalformedPayload { tx_type, source }
                })?;
                Ok(Self::new(
                    payload.seqno,
                    MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(
                        payload.pub_key,
                    ))),
                    payload.signatures,
                ))
            }
            AdminTxType::OlStfVkUpdate => {
                Self::decode_predicate_update_payload(tx_type, bytes, ProofType::OLStf)
            }
            AdminTxType::AsmStfVkUpdate => {
                Self::decode_predicate_update_payload(tx_type, bytes, ProofType::Asm)
            }
        }
    }

    /// Encodes the tx-type-specific flat SSZ payload carried inside the witness envelope.
    pub fn payload_bytes(&self) -> Vec<u8> {
        match &self.action {
            MultisigAction::Cancel(cancel) => CancelPayload {
                seqno: self.seqno,
                target_id: *cancel.target_id(),
                signatures: self.signatures.clone(),
            }
            .as_ssz_bytes(),
            MultisigAction::Update(update) => match update {
                UpdateAction::Multisig(multisig) => MultisigUpdatePayload {
                    seqno: self.seqno,
                    add_members: multisig.config().add_members().to_vec(),
                    remove_members: multisig.config().remove_members().to_vec(),
                    new_threshold: multisig.config().new_threshold().get(),
                    signatures: self.signatures.clone(),
                }
                .as_ssz_bytes(),
                UpdateAction::OperatorSet(operator) => OperatorUpdatePayload {
                    seqno: self.seqno,
                    add_members: operator.add_members().to_vec(),
                    remove_members: operator.remove_members().to_vec(),
                    signatures: self.signatures.clone(),
                }
                .as_ssz_bytes(),
                UpdateAction::Sequencer(sequencer) => SequencerUpdatePayload {
                    seqno: self.seqno,
                    pub_key: *sequencer.pub_key(),
                    signatures: self.signatures.clone(),
                }
                .as_ssz_bytes(),
                UpdateAction::VerifyingKey(predicate) => PredicateUpdatePayload {
                    seqno: self.seqno,
                    key: predicate.key().clone(),
                    signatures: self.signatures.clone(),
                }
                .as_ssz_bytes(),
            },
        }
    }

    fn decode_multisig_update_payload(
        tx_type: AdminTxType,
        bytes: &[u8],
        role: Role,
    ) -> Result<Self, AdministrationTxParseError> {
        let payload = MultisigUpdatePayload::from_ssz_bytes(bytes)
            .map_err(|source| AdministrationTxParseError::MalformedPayload { tx_type, source })?;
        let new_threshold = NonZero::new(payload.new_threshold)
            .ok_or(AdministrationTxParseError::InvalidThreshold { tx_type })?;
        let config =
            ThresholdConfigUpdate::new(payload.add_members, payload.remove_members, new_threshold);
        Ok(Self::new(
            payload.seqno,
            MultisigAction::Update(UpdateAction::Multisig(MultisigUpdate::new(config, role))),
            payload.signatures,
        ))
    }

    fn decode_predicate_update_payload(
        tx_type: AdminTxType,
        bytes: &[u8],
        kind: ProofType,
    ) -> Result<Self, AdministrationTxParseError> {
        let payload = PredicateUpdatePayload::from_ssz_bytes(bytes)
            .map_err(|source| AdministrationTxParseError::MalformedPayload { tx_type, source })?;
        Ok(Self::new(
            payload.seqno,
            MultisigAction::Update(UpdateAction::VerifyingKey(PredicateUpdate::new(
                payload.key,
                kind,
            ))),
            payload.signatures,
        ))
    }
}
