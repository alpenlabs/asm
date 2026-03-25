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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Arbitrary, Encode, Decode)]
pub struct WithdrawOutput {
    /// Bitcoin Output Script Descriptor specifying the destination address.
    #[ssz(with = "descriptor_ssz")]
    pub destination: Descriptor,

    /// Amount to withdraw (in satoshis).
    pub amt: BitcoinAmount,
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
struct DispatchWithdrawalPayload {
    output: WithdrawOutput,
    selected_operator: OperatorSelection,
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

#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod descriptor_ssz {
    use super::Descriptor;

    pub mod encode {
        use ssz::Encode as SszEncode;

        use super::Descriptor;

        pub fn is_ssz_fixed_len() -> bool {
            <Vec<u8> as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <Vec<u8> as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &Descriptor) -> usize {
            value.to_bytes().ssz_bytes_len()
        }

        pub fn ssz_append(value: &Descriptor, buf: &mut Vec<u8>) {
            value.to_bytes().ssz_append(buf);
        }
    }

    pub mod decode {
        use ssz::{Decode as SszDecode, DecodeError};

        use super::Descriptor;

        pub fn is_ssz_fixed_len() -> bool {
            <Vec<u8> as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <Vec<u8> as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Descriptor, DecodeError> {
            let descriptor_bytes = Vec::<u8>::from_ssz_bytes(bytes)?;
            Descriptor::from_bytes(&descriptor_bytes)
                .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
        }
    }
}
