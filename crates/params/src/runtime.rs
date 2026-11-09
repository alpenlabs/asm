use serde::{Deserialize, Serialize};
use strata_asm_admin_types::ConfirmationDepths;

/// Values that specs after genesis read while they execute, one section per spec.
///
/// A section belongs to the spec it is named after, and no other spec reads it. A spec that
/// reads a section runs inside the proof guest too, so its guest has to bake that section in,
/// and its predicate then commits to the values. Because each guest bakes only its own section,
/// adding a section for a later spec leaves every earlier spec's guest unchanged.
///
/// Every section is optional, because a network only needs one for a spec it runs. Unknown
/// sections are ignored, so a binary that predates a spec still reads a file that configures it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmRuntimeParams {
    /// Values for spec 2, which installs them when it takes over from an earlier spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_v2: Option<SpecV2Params>,
}

/// The section of [`AsmRuntimeParams`] that spec 2 reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecV2Params {
    /// Confirmation depths spec 2 writes into the administration state, replacing the ones the
    /// chain started with.
    pub confirmation_depths: ConfirmationDepths,
}
