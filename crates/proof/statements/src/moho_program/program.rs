//! [`MohoProgram`] implementation for the ASM STF.
//!
//! This module contains the [`AsmStfProgram`] type that implements [`MohoProgram`], wiring the
//! ASM state transition function into the Moho runtime. It handles state commitment via SSZ tree
//! hashing,
//! transition execution, and extraction of post-transition artifacts such as predicate updates
//! and export state entries.
use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, InnerStateCommitment, StateReference};
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_logs::{AsmStfUpdate, NewExportEntry};
use strata_asm_spec::StrataAsmSpec;
use strata_asm_stf::{compute_asm_transition, AsmStfOutput};
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher, TreeHash};

use crate::moho_program::input::AsmStepInput;

/// Extracts the next [`PredicateKey`] advertised by an STF step, if any.
///
/// Scans `logs` for an [`AsmStfUpdate`] entry and returns the new predicate.
/// When no update is emitted the caller should carry the previous predicate
/// forward.
pub fn extract_next_predicate_from_logs(logs: &[AsmLogEntry]) -> Option<PredicateKey> {
    logs.iter().find_map(|log| {
        log.try_into_log::<AsmStfUpdate>()
            .ok()
            .map(|update| update.new_predicate().clone())
    })
}

/// Applies each [`NewExportEntry`] in `logs` to `prev`, returning the updated
/// export state.
pub fn advance_export_state_with_logs(mut prev: ExportState, logs: &[AsmLogEntry]) -> ExportState {
    for log in logs {
        if let Ok(export) = log.try_into_log::<NewExportEntry>() {
            prev.add_entry(export.container_id(), *export.entry_data())
                .expect("failed to add entry");
        }
    }
    prev
}

/// The ASM STF program adapted for the Moho runtime.
///
/// Implements [`MohoProgram`] to define how L1 Bitcoin blocks drive ASM state transitions
/// within the recursive proof system. Each step validates a block, executes the ASM STF,
/// and produces updated state, predicate keys, and export entries.
#[derive(Debug)]
pub struct AsmStfProgram;

impl MohoProgram for AsmStfProgram {
    type State = AnchorState;

    type StepInput = AsmStepInput;

    type Spec = StrataAsmSpec;

    type StepOutput = AsmStfOutput;

    fn compute_input_reference(input: &AsmStepInput) -> StateReference {
        input.compute_ref()
    }

    fn extract_prev_reference(input: &Self::StepInput) -> StateReference {
        input.compute_prev_ref()
    }

    fn compute_state_commitment(state: &AnchorState) -> InnerStateCommitment {
        let state_commitment_root = TreeHash::<Sha256Hasher>::tree_hash_root(state);
        InnerStateCommitment::new(state_commitment_root.0)
    }

    fn process_transition(
        pre_state: &AnchorState,
        spec: &StrataAsmSpec,
        input: &AsmStepInput,
    ) -> AsmStfOutput {
        compute_asm_transition(
            spec,
            pre_state,
            input.block(),
            input.aux_data(),
            input.coinbase_inclusion_proof(),
        )
        .expect("asm: compute transition")
    }

    fn extract_post_state(output: &Self::StepOutput) -> &Self::State {
        &output.state
    }

    fn extract_next_predicate(output: &Self::StepOutput) -> Option<PredicateKey> {
        extract_next_predicate_from_logs(&output.manifest.logs)
    }

    fn compute_next_export_state(prev: ExportState, output: &Self::StepOutput) -> ExportState {
        advance_export_state_with_logs(prev, &output.manifest.logs)
    }
}
