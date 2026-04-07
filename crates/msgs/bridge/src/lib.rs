//! Inter-protocol message types for the bridge subprotocol.
//!
//! This crate exposes the incoming bridge messages and shared withdrawal output
//! payload so other subprotocols can dispatch withdrawals without pulling in the
//! bridge implementation crate.

use std::any::Any;

use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_txs_bridge_v1::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_bridge_types::{OperatorIdx, OperatorSelection, WithdrawOutput};
use strata_crypto::EvenPublicKey;

/// Incoming message types received from other subprotocols.
///
/// This enum represents all possible message types that the bridge subprotocol can
/// receive from other subprotocols in the ASM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeIncomingMsg {
    /// Emitted after a checkpoint proof has been validated. Contains the withdrawal command
    /// specifying the destination descriptor and amount to be withdrawn.
    DispatchWithdrawal {
        /// The withdrawal output (destination + amount).
        output: WithdrawOutput,
        /// User's operator selection for withdrawal assignment.
        selected_operator: OperatorSelection,
    },

    /// Emitted by the admin subprotocol when the operator set is updated.
    /// Adds new operators by public key and removes existing operators by index.
    UpdateOperatorSet {
        /// Operator public keys to add to the bridge multisig.
        add_members: Vec<EvenPublicKey>,
        /// Operator indices to remove from the bridge multisig.
        remove_members: Vec<OperatorIdx>,
    },
}

#[derive(Debug, Encode, Decode)]
struct DispatchWithdrawalPayload {
    output: WithdrawOutput,
    selected_operator: OperatorSelection,
}

#[derive(Debug, Encode, Decode)]
struct UpdateOperatorSetPayload {
    add_members: Vec<EvenPublicKey>,
    remove_members: Vec<OperatorIdx>,
}

impl SszEncode for BridgeIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            Self::DispatchWithdrawal {
                output,
                selected_operator,
            } => {
                0_u8.ssz_append(buf);
                DispatchWithdrawalPayload {
                    output: output.clone(),
                    selected_operator: *selected_operator,
                }
                .ssz_append(buf);
            }
            Self::UpdateOperatorSet {
                add_members,
                remove_members,
            } => {
                1_u8.ssz_append(buf);
                UpdateOperatorSetPayload {
                    add_members: add_members.clone(),
                    remove_members: remove_members.clone(),
                }
                .ssz_append(buf);
            }
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        match self {
            Self::DispatchWithdrawal {
                output,
                selected_operator,
            } => {
                1 + DispatchWithdrawalPayload {
                    output: output.clone(),
                    selected_operator: *selected_operator,
                }
                .ssz_bytes_len()
            }
            Self::UpdateOperatorSet {
                add_members,
                remove_members,
            } => {
                1 + UpdateOperatorSetPayload {
                    add_members: add_members.clone(),
                    remove_members: remove_members.clone(),
                }
                .ssz_bytes_len()
            }
        }
    }
}

impl SszDecode for BridgeIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (tag_bytes, payload_bytes) = bytes.split_first().ok_or_else(|| {
            DecodeError::BytesInvalid("missing bridge message variant tag".into())
        })?;

        match *tag_bytes {
            0 => {
                let payload = DispatchWithdrawalPayload::from_ssz_bytes(payload_bytes)?;
                Ok(Self::DispatchWithdrawal {
                    output: payload.output,
                    selected_operator: payload.selected_operator,
                })
            }
            1 => {
                let payload = UpdateOperatorSetPayload::from_ssz_bytes(payload_bytes)?;
                Ok(Self::UpdateOperatorSet {
                    add_members: payload.add_members,
                    remove_members: payload.remove_members,
                })
            }
            tag => Err(DecodeError::BytesInvalid(format!(
                "unknown bridge message variant tag {tag}"
            ))),
        }
    }
}

impl InterprotoMsg for BridgeIncomingMsg {
    fn id(&self) -> SubprotocolId {
        BRIDGE_V1_SUBPROTOCOL_ID
    }

    fn as_dyn_any(&self) -> &dyn Any {
        self
    }
}
