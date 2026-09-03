//! [`MohoProgram`] implementation for the ASM STF.
//!
//! This module contains the [`AsmStfProgram`] type that implements [`MohoProgram`], wiring the
//! ASM state transition function into the Moho runtime. It handles state commitment via SSZ tree
//! hashing,
//! transition execution, and extraction of post-transition artifacts such as predicate updates
//! and export state entries.
//!
//! The program is generic over the [`AsmSpec`] it executes. One instantiation
//! becomes one guest artifact: the specification is fixed at compile time, so a
//! built artifact cannot be talked into running rules other than the ones it was
//! built for. Which artifact executes a block is decided outside the guest, by
//! the predicate the parent handed over — the value the recursive proof already
//! verifies each step against.
use std::{fmt, marker::PhantomData};

use moho_runtime_interface::MohoProgram;
use moho_types::{ExportContainer, ExportState, InnerStateCommitment, StateReference};
use strata_asm_common::{prepare_state, AnchorState, AsmLogEntry, AsmSpec};
use strata_asm_logs::{ExportExtraDataUpdate, NewExportEntry};
use strata_asm_spec::{StrataAsmSpecV0, StrataAsmSpecV1};
use strata_asm_stf::{compute_asm_transition, AsmStfOutput};
use strata_predicate::PredicateKey;
use tree_hash::{Sha256Hasher, TreeHash};

use crate::moho_program::input::AsmStepInput;

/// The ASM STF program executing the released (`v0`) rules.
pub type AsmStfProgramV0 = AsmStfProgram<StrataAsmSpecV0>;

/// The ASM STF program executing the current (`v1`) rules.
pub type AsmStfProgramV1 = AsmStfProgram<StrataAsmSpecV1>;

/// Commits to an [`AnchorState`] as a Moho inner state.
///
/// A free function rather than a method: the commitment is a property of the
/// state's encoding alone, identical under every specification. Callers that
/// only need the commitment — the Moho worker deriving each block's `MohoState`
/// — therefore do not have to name a specification to get it.
pub fn compute_anchor_state_commitment(state: &AnchorState) -> InnerStateCommitment {
    let state_commitment_root = TreeHash::tree_hash_root::<Sha256Hasher>(state);
    InnerStateCommitment::new(state_commitment_root.0)
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
///
/// `S` is the specification this instantiation executes; see the module docs for
/// why it is a type parameter rather than a runtime value.
pub struct AsmStfProgram<S>(PhantomData<fn() -> S>);

// Hand-written rather than derived: the derive would add an `S: Debug` bound,
// which is unnecessary — the type holds no `S`, only a marker.
impl<S> fmt::Debug for AsmStfProgram<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AsmStfProgram")
    }
}

impl<S: AsmSpec> MohoProgram for AsmStfProgram<S> {
    type State = AnchorState;

    type StepInput = AsmStepInput;

    type Spec = S;

    type StepOutput = AsmStfOutput;

    fn compute_input_reference(input: &AsmStepInput) -> StateReference {
        input.compute_ref()
    }

    fn extract_prev_reference(input: &Self::StepInput) -> StateReference {
        input.compute_prev_ref()
    }

    fn compute_state_commitment(state: &AnchorState) -> InnerStateCommitment {
        compute_anchor_state_commitment(state)
    }

    fn process_transition(
        pre_state: &AnchorState,
        _spec: &S,
        input: &AsmStepInput,
    ) -> AsmStfOutput {
        // Preparation runs inside proven execution, so a boundary migration is
        // committed and proven as part of this block. The decision uses only
        // this spec's schema and the codec versions in `pre_state`, both of
        // which a native worker sees identically — nothing here consults a
        // height or a schedule the guest could not reproduce.
        let prepared = prepare_state::<S>(pre_state)
            .unwrap_or_else(|e| panic!("asm: state preparation failed: {e}"));

        compute_asm_transition(
            &prepared,
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
        strata_asm_logs::extract_next_predicate_from_logs(&output.manifest.logs)
    }

    fn compute_next_export_state(prev: ExportState, output: &Self::StepOutput) -> ExportState {
        advance_export_state_with_logs(prev, &output.manifest.logs)
    }
}
