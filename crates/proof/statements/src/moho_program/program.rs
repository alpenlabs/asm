//! [`MohoProgram`] implementation for the ASM STF.
//!
//! This module contains the [`AsmStfProgram`] type that implements [`MohoProgram`], wiring the
//! ASM state transition function into the Moho runtime. It handles state commitment via SSZ tree
//! hashing,
//! transition execution, and extraction of post-transition artifacts such as predicate updates
//! and export state entries.
use moho_runtime_interface::MohoProgram;
use moho_types::{ExportContainer, ExportState, InnerStateCommitment, StateReference};
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_logs::{AsmStfUpdate, ExportExtraDataUpdate, NewExportEntry};
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

/// Applies each export-related log in `logs` to `prev`, returning the updated
/// export state.
///
/// [`NewExportEntry`] appends to the target container's MMR, while
/// [`ExportExtraDataUpdate`] overwrites the target container's `extra_data`.
/// Both create the container on first reference.
pub fn advance_export_state_with_logs(prev: ExportState, logs: &[AsmLogEntry]) -> ExportState {
    let mut containers = prev.containers().to_vec();
    for log in logs {
        if let Ok(export) = log.try_into_log::<NewExportEntry>() {
            container_mut(&mut containers, export.container_id())
                .add_entry(*export.entry_data())
                .expect("failed to add entry");
        } else if let Ok(update) = log.try_into_log::<ExportExtraDataUpdate>() {
            container_mut(&mut containers, update.container_id())
                .update_extra_data(*update.extra_data());
        }
    }
    ExportState::new(containers).expect("export container count stays within capacity")
}

/// Returns a mutable reference to the container with `container_id`, creating
/// and appending an empty one if it does not already exist.
fn container_mut(containers: &mut Vec<ExportContainer>, container_id: u8) -> &mut ExportContainer {
    if let Some(pos) = containers
        .iter()
        .position(|c| c.container_id() == container_id)
    {
        &mut containers[pos]
    } else {
        containers.push(ExportContainer::new(container_id));
        containers.last_mut().expect("just pushed a container")
    }
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
        let state_commitment_root = TreeHash::tree_hash_root::<Sha256Hasher>(state);
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
        .unwrap_or_else(|e| panic!("asm: compute transition failed: {e}"))
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
