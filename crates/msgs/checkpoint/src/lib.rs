//! Inter-protocol message types for the checkpoint subprotocol.
//!
//! This crate exposes the incoming message enum consumed by checkpoint subprotocols so other
//! subprotocols can send configuration updates or deposit notifications without depending on
//! the checkpoint implementation crate.

use std::any::Any;

use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_txs_checkpoint::CHECKPOINT_SUBPROTOCOL_ID;
use strata_asm_txs_checkpoint_v0::CHECKPOINT_V0_SUBPROTOCOL_ID;
use strata_predicate::PredicateKey;
use strata_primitives::{buf::Buf32, l1::BitcoinAmount};

/// Incoming messages for checkpoint subprotocols.
///
/// Messages are routed to both the checkpoint-v0 and the new checkpoint.
/// Admin configuration updates target both, while deposit notifications
/// target the new checkpoint subprotocol.
#[derive(Clone, Debug)]
pub enum CheckpointIncomingMsg {
    /// Update the Schnorr public key used to verify sequencer signatures embedded in checkpoints.
    // TODO: (@PG) make this directly take PredicateKey
    UpdateSequencerKey(Buf32),

    /// Update the rollup proving system verifying key used for Groth16 proof verification.
    UpdateCheckpointPredicate(PredicateKey),

    /// Notification that a deposit has been processed by the bridge subprotocol.
    DepositProcessed(BitcoinAmount),
}

#[derive(Debug, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
enum CheckpointIncomingMsgSsz {
    UpdateSequencerKey(Buf32),
    UpdateCheckpointPredicate(PredicateKey),
    DepositProcessed(BitcoinAmount),
}

impl From<&CheckpointIncomingMsg> for CheckpointIncomingMsgSsz {
    fn from(value: &CheckpointIncomingMsg) -> Self {
        match value {
            CheckpointIncomingMsg::UpdateSequencerKey(key) => Self::UpdateSequencerKey(*key),
            CheckpointIncomingMsg::UpdateCheckpointPredicate(predicate) => {
                Self::UpdateCheckpointPredicate(predicate.clone())
            }
            CheckpointIncomingMsg::DepositProcessed(amount) => Self::DepositProcessed(*amount),
        }
    }
}

impl From<CheckpointIncomingMsgSsz> for CheckpointIncomingMsg {
    fn from(value: CheckpointIncomingMsgSsz) -> Self {
        match value {
            CheckpointIncomingMsgSsz::UpdateSequencerKey(key) => Self::UpdateSequencerKey(key),
            CheckpointIncomingMsgSsz::UpdateCheckpointPredicate(predicate) => {
                Self::UpdateCheckpointPredicate(predicate)
            }
            CheckpointIncomingMsgSsz::DepositProcessed(amount) => Self::DepositProcessed(amount),
        }
    }
}

impl SszEncode for CheckpointIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        CheckpointIncomingMsgSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        CheckpointIncomingMsgSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for CheckpointIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(CheckpointIncomingMsgSsz::from_ssz_bytes(bytes)?.into())
    }
}

impl InterprotoMsg for CheckpointIncomingMsg {
    fn id(&self) -> SubprotocolId {
        match self {
            // Admin config updates target checkpoint V0.
            Self::UpdateSequencerKey(_) | Self::UpdateCheckpointPredicate(_) => {
                CHECKPOINT_V0_SUBPROTOCOL_ID
            }
            // Deposit notifications target the new checkpoint subprotocol.
            Self::DepositProcessed(_) => CHECKPOINT_SUBPROTOCOL_ID,
        }
    }

    fn as_dyn_any(&self) -> &dyn Any {
        self
    }
}
