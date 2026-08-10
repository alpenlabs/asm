//! Inter-protocol message types for the administration subprotocol.
//!
//! This crate exposes the incoming message enum consumed by the administration subprotocol so
//! checkpoint can acknowledge a promoted OL predicate transition without depending on the
//! administration implementation crate.

use std::any::Any;

use strata_asm_checkpoint_types::PendingTransitionCount;
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_proto_admin_txs::constants::ADMINISTRATION_SUBPROTOCOL_ID;

/// Incoming messages for the administration subprotocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdministrationIncomingMsg {
    /// Reports how many pending predicate transitions a checkpoint promotion pruned.
    ///
    /// Checkpoint state is not observable from administration state, so this acknowledgement
    /// keeps administration's post-enactment occupancy accounting synchronized.
    OlTransitionsPruned(PendingTransitionCount),
}

impl InterprotoMsg for AdministrationIncomingMsg {
    fn id(&self) -> SubprotocolId {
        ADMINISTRATION_SUBPROTOCOL_ID
    }

    fn as_dyn_any(&self) -> &dyn Any {
        self
    }
}
