//! Derivation of [`MohoState`] from committed ASM anchor states.
//!
//! The Moho state is a thin projection of the ASM anchor state: the inner
//! commitment is the tree hash of the anchor state, while the predicate and
//! export state are advanced by replaying the STF logs the ASM worker recorded
//! for the block. Neither requires re-running the STF — everything needed lives
//! in the committed [`AnchorState`] and its [`AsmLogEntry`]s.

use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState};
use strata_asm_common::{AnchorState, AsmLogEntry};
use strata_asm_proof_impl::moho_program::program::{
    AsmStfProgram, advance_export_state_with_logs, extract_next_predicate_from_logs,
};
use strata_predicate::PredicateKey;

/// Seeds the genesis [`MohoState`]: there is no prior state to chain forward
/// from, so we pair the genesis anchor commitment with the configured
/// `asm_predicate` and an empty export state.
pub(crate) fn construct_genesis_moho_state(
    asm_predicate: PredicateKey,
    genesis: &AnchorState,
) -> MohoState {
    let inner = AsmStfProgram::compute_state_commitment(genesis);
    let export_state = ExportState::new(vec![]).expect("empty export state is always valid");
    MohoState::new(inner, asm_predicate, export_state)
}

/// Chains the [`MohoState`] forward from its parent: the STF logs drive the
/// predicate and export-state updates, and the inner commitment is recomputed
/// from the new anchor state.
pub(crate) fn construct_next_moho_state(
    prev: &MohoState,
    anchor_state: &AnchorState,
    logs: &[AsmLogEntry],
) -> MohoState {
    let next_predicate =
        extract_next_predicate_from_logs(logs).unwrap_or_else(|| prev.next_predicate().clone());
    let next_export_state = advance_export_state_with_logs(prev.export_state().clone(), logs);
    let inner = AsmStfProgram::compute_state_commitment(anchor_state);
    MohoState::new(inner, next_predicate, next_export_state)
}
