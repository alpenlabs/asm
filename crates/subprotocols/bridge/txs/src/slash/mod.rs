//! Slash Transaction Parser
//!
//! This module provides functionality for parsing Bitcoin slash transactions
//! that follow the SPS-50 specification for the Strata bridge protocol.
//!
//! ## Slash Transaction Structure
//!
//! A slash transaction is posted by a watchtower if the claim was contested but the operator hasn't
//! posted the Contested Payout Transaction within the allotted time frame. The transaction spends
//! the operator stake and distributes it to watchtowers.
//!
//! ### Inputs
//! - 1. **Contest slash connector**: Locked to the N-of-N multisig with a relative timelock
//! - 2. **Stake connector**: Locked to the N-of-N multisig..
//!
//! Only the stake connector is validated. ASM does not store the relative timelock, so it cannot
//! check the contest connector, and does not need to: the stake connector is spent with
//! `SIGHASH_ALL`, whose taproot sighash commits to every input's outpoint, value and script, so
//! that signature already binds input 0.
//!
//! Matching the script does not prove the stake connector belongs to the operator being slashed:
//! all operators active in the same N/N configuration share one script, so a match only shows which
//! configuration was in force. The operator index comes from the aux data, and only presigning ties
//! it to the stake connector being spent.
//!
//! ### Outputs
//!
//! 1. **OP_RETURN Output (Index 0)** (required): Contains SPS-50 tagged data with
//!     - Magic number (4 bytes): Protocol instance identifier
//!     - Subprotocol ID (1 byte): Bridge v1 subprotocol identifier
//!     - Transaction type (1 byte): Slash transaction type
//!     - Auxiliary data (4 bytes):
//!         - Operator index (4 bytes, encoded using [`strata_codec::Codec`] which uses big-endian)
//!
//! Additional outputs distribute the stake to watchtowers, but ASM skips validating them because
//! correctness is assumed to be enforced during presigning as they spend from the same N/N
//! multisig.

mod aux_input;
mod info;
mod parse;

pub use aux_input::SlashTxHeaderAux;
pub use info::SlashInfo;
pub use parse::{STAKE_INPUT_INDEX, parse_slash_tx};
