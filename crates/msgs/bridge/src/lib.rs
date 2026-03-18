//! Inter-protocol message types for the bridge subprotocol.
//!
//! This crate exposes the incoming bridge messages and shared withdrawal output
//! payload so other subprotocols can dispatch withdrawals without pulling in the
//! bridge implementation crate.

use std::any::Any;

use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_asm_common::{InterprotoMsg, SubprotocolId};
use strata_asm_txs_bridge_v1::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_bridge_types::OperatorSelection;
use strata_primitives::{bitcoin_bosd::Descriptor, l1::BitcoinAmount};

/// Bitcoin output specification for a withdrawal operation.
///
/// Each withdrawal output specifies a destination address (as a Bitcoin descriptor)
/// and the amount to be sent. This structure provides all information needed by
/// operators to construct the appropriate Bitcoin transaction output.
///
/// # Bitcoin Descriptors
///
/// The destination uses Bitcoin Output Script Descriptors (BOSD), which provide
/// a standardized way to specify Bitcoin addresses and locking conditions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary)]
pub struct WithdrawOutput {
    /// Bitcoin Output Script Descriptor specifying the destination address.
    pub destination: Descriptor,

    /// Amount to withdraw (in satoshis).
    pub amt: BitcoinAmount,
}

#[derive(Debug, Encode, Decode)]
struct WithdrawOutputSsz {
    destination: Vec<u8>,
    amt: BitcoinAmount,
}

impl From<&WithdrawOutput> for WithdrawOutputSsz {
    fn from(value: &WithdrawOutput) -> Self {
        Self {
            destination: value.destination.to_bytes(),
            amt: value.amt,
        }
    }
}

impl TryFrom<WithdrawOutputSsz> for WithdrawOutput {
    type Error = DecodeError;

    fn try_from(value: WithdrawOutputSsz) -> Result<Self, Self::Error> {
        let destination = Descriptor::from_bytes(&value.destination)
            .map_err(|err| DecodeError::BytesInvalid(err.to_string()))?;
        Ok(Self::new(destination, value.amt))
    }
}

impl SszEncode for WithdrawOutput {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        WithdrawOutputSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        WithdrawOutputSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for WithdrawOutput {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        WithdrawOutputSsz::from_ssz_bytes(bytes)?.try_into()
    }
}

impl WithdrawOutput {
    /// Creates a new withdrawal output with the specified destination and amount.
    pub fn new(destination: Descriptor, amt: BitcoinAmount) -> Self {
        Self { destination, amt }
    }

    /// Returns a reference to the destination descriptor.
    pub fn destination(&self) -> &Descriptor {
        &self.destination
    }

    /// Returns the withdrawal amount.
    pub fn amt(&self) -> BitcoinAmount {
        self.amt
    }
}

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
}

#[derive(Debug, Encode, Decode)]
struct DispatchWithdrawalSsz {
    output: WithdrawOutputSsz,
    selected_operator: OperatorSelection,
}

#[derive(Debug, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
enum BridgeIncomingMsgSsz {
    DispatchWithdrawal(DispatchWithdrawalSsz),
}

impl From<&BridgeIncomingMsg> for BridgeIncomingMsgSsz {
    fn from(value: &BridgeIncomingMsg) -> Self {
        match value {
            BridgeIncomingMsg::DispatchWithdrawal {
                output,
                selected_operator,
            } => Self::DispatchWithdrawal(DispatchWithdrawalSsz {
                output: output.into(),
                selected_operator: *selected_operator,
            }),
        }
    }
}

impl TryFrom<BridgeIncomingMsgSsz> for BridgeIncomingMsg {
    type Error = DecodeError;

    fn try_from(value: BridgeIncomingMsgSsz) -> Result<Self, Self::Error> {
        match value {
            BridgeIncomingMsgSsz::DispatchWithdrawal(payload) => {
                let output = payload.output.try_into()?;
                Ok(Self::DispatchWithdrawal {
                    output,
                    selected_operator: payload.selected_operator,
                })
            }
        }
    }
}

impl SszEncode for BridgeIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        BridgeIncomingMsgSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        BridgeIncomingMsgSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for BridgeIncomingMsg {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        BridgeIncomingMsgSsz::from_ssz_bytes(bytes)?.try_into()
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
