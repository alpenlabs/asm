//! Inter-protocol message types for the bridge subprotocol.
//!
//! This crate exposes the incoming bridge messages and shared withdrawal output
//! payload so other subprotocols can dispatch withdrawals without pulling in the
//! bridge implementation crate.

use std::any::Any;

use ssz_derive::{Decode, Encode};
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_proto_bridge_v1_types::{OperatorIdx, OperatorSelection, WithdrawOutput};
use strata_crypto::EvenPublicKey;

/// Incoming message types received from other subprotocols.
///
/// This enum represents all possible message types that the bridge subprotocol can
/// receive from other subprotocols in the ASM.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum BridgeIncomingMsg {
    /// Emitted after a checkpoint proof has been validated. Contains the withdrawal command
    /// specifying the destination descriptor and amount to be withdrawn.
    DispatchWithdrawal(DispatchWithdrawalPayload),

    /// Emitted by the admin subprotocol when the operator set is updated.
    /// Adds new operators by public key and removes existing operators by index.
    UpdateOperatorSet(UpdateOperatorSetPayload),

    /// Emergency signal from the admin subprotocol that activates the safe harbour address.
    Defcon1(Defcon1Payload),
}

/// Payload for [`BridgeIncomingMsg::DispatchWithdrawal`].
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct DispatchWithdrawalPayload {
    /// The withdrawal output (destination + amount).
    pub output: WithdrawOutput,
    /// User's operator selection for withdrawal assignment.
    pub selected_operator: OperatorSelection,
}

/// Payload for [`BridgeIncomingMsg::UpdateOperatorSet`].
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct UpdateOperatorSetPayload {
    /// Operator public keys to add to the bridge multisig.
    pub add_members: Vec<EvenPublicKey>,
    /// Operator indices to remove from the bridge multisig.
    pub remove_members: Vec<OperatorIdx>,
}

/// Empty marker payload for [`BridgeIncomingMsg::Defcon1`]; the signal itself carries no data.
#[derive(Clone, Debug, Eq, PartialEq, Default, Encode, Decode)]
pub struct Defcon1Payload {}

impl InterprotoMsg for BridgeIncomingMsg {
    fn id(&self) -> SubprotocolId {
        BRIDGE_V1_SUBPROTOCOL_ID
    }

    fn as_dyn_any(&self) -> &dyn Any {
        self
    }
}
