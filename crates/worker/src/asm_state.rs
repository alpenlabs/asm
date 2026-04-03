//! ASM bookkeeping state.
//!
//! Previously lived in `strata-state` (alpen). Moved here to eliminate the
//! circular dependency between the ASM repo and alpen.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_stf::AsmStfOutput;

/// ASM bookkeeping "umbrella" state.
///
/// Wraps an [`AnchorState`] (the raw STF output) with log entries.
/// This is the unit stored in the database per L1 block.
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AsmState {
    state: AnchorState,
    logs: Vec<AsmLogEntry>,
}

impl AsmState {
    pub fn new(state: AnchorState, logs: Vec<AsmLogEntry>) -> Self {
        Self { state, logs }
    }

    pub fn from_output(output: AsmStfOutput) -> Self {
        Self {
            state: output.state,
            logs: output.manifest.logs.to_vec(),
        }
    }

    pub fn logs(&self) -> &Vec<AsmLogEntry> {
        &self.logs
    }

    pub fn state(&self) -> &AnchorState {
        &self.state
    }
}
