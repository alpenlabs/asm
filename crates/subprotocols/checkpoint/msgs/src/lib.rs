//! Inter-protocol message types for the checkpoint subprotocol.
//!
//! This crate exposes the incoming message enum consumed by checkpoint subprotocols so other
//! subprotocols can send configuration updates or deposit notifications without depending on
//! the checkpoint implementation crate.

use std::any::Any;

use ssz_derive::{Decode, Encode};
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_proto_checkpoint_txs::CHECKPOINT_SUBPROTOCOL_ID;
use strata_btc_types::BitcoinAmount;
use strata_predicate::PredicateKey;

/// Incoming messages for the checkpoint subprotocol.
///
/// Carries admin configuration updates and deposit notifications from
/// other subprotocols.
#[derive(Clone, Debug, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum CheckpointIncomingMsg {
    /// Update the Schnorr public key used to verify sequencer signatures embedded in checkpoints.
    ///
    /// The canonical wire representation is the full predicate key so both checkpoint
    /// subprotocols consume the same SSZ-native type.
    UpdateSequencerKey(PredicateKey),

    /// Update the rollup proving system verifying key used for Groth16 proof verification.
    UpdateCheckpointPredicate(PredicateKey),

    /// Notification that a deposit has been processed by the bridge subprotocol.
    DepositProcessed(BitcoinAmount),
}

impl InterprotoMsg for CheckpointIncomingMsg {
    fn id(&self) -> SubprotocolId {
        CHECKPOINT_SUBPROTOCOL_ID
    }

    fn as_dyn_any(&self) -> &dyn Any {
        self
    }
}
