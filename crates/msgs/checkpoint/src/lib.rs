//! Inter-protocol message types for the checkpoint subprotocol.
//!
//! This crate exposes the incoming message enum consumed by checkpoint subprotocols so other
//! subprotocols can send configuration updates or deposit notifications without depending on
//! the checkpoint implementation crate.

use std::any::Any;

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use strata_asm_common::{
    InterprotoMsg, SubprotocolId, from_ssz_bytes_via_serde_json, ssz_append_via_serde_json,
    ssz_bytes_len_via_serde_json,
};
use strata_asm_txs_checkpoint::CHECKPOINT_SUBPROTOCOL_ID;
use strata_predicate::PredicateKey;
use strata_primitives::{buf::Buf32, l1::BitcoinAmount};

/// Incoming messages for checkpoint subprotocols.
///
/// Messages are routed to both the checkpoint-v0 and the new checkpoint.
/// Admin configuration updates target both, while deposit notifications
/// target the new checkpoint subprotocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CheckpointIncomingMsg {
    /// Update the Schnorr public key used to verify sequencer signatures embedded in checkpoints.
    // TODO: (@PG) make this directly take PredicateKey
    UpdateSequencerKey(Buf32),

    /// Update the rollup proving system verifying key used for Groth16 proof verification.
    UpdateCheckpointPredicate(PredicateKey),

    /// Notification that a deposit has been processed by the bridge subprotocol.
    DepositProcessed(BitcoinAmount),
}

impl Encode for CheckpointIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        ssz_append_via_serde_json(self, buf, "checkpoint incoming message");
    }

    fn ssz_bytes_len(&self) -> usize {
        ssz_bytes_len_via_serde_json(self, "checkpoint incoming message")
    }
}

impl Decode for CheckpointIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_ssz_bytes_via_serde_json(bytes)
    }
}

impl InterprotoMsg for CheckpointIncomingMsg {
    fn id(&self) -> SubprotocolId {
        CHECKPOINT_SUBPROTOCOL_ID
    }

    fn as_dyn_any(&self) -> &dyn Any {
        self
    }
}
