//! Inter-protocol message types for the checkpoint subprotocol.
//!
//! This crate exposes the incoming message enum consumed by checkpoint subprotocols so other
//! subprotocols can send configuration updates or deposit notifications without depending on
//! the checkpoint implementation crate.

use std::any::Any;

use ssz_derive::{Decode, Encode};
use strata_asm_checkpoint_types::PendingPredicateTransition;
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_proto_checkpoint_txs::CHECKPOINT_SUBPROTOCOL_ID;
use strata_btc_types::BitcoinAmount;
use strata_identifiers::Buf32;

/// Incoming messages for the checkpoint subprotocol.
///
/// Carries admin configuration updates and deposit notifications from
/// other subprotocols.
#[derive(Clone, Debug, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum CheckpointIncomingMsg {
    /// Update the x-only BIP340 Schnorr public key that authenticates checkpoint envelopes.
    ///
    /// The envelope container fixes this key to BIP340, so it travels as bare key bytes
    /// rather than a predicate.
    UpdateSequencerKey(Buf32),

    /// Queue an enacted rollup proving-system predicate transition.
    QueueCheckpointPredicateTransition(PendingPredicateTransition),

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
