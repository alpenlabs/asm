use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_asm_admin_types::ConfirmationDepths;

/// Values that specs after genesis read while they execute, one section per spec.
///
/// A section belongs to the spec it is named after, and no other spec reads it. A spec that
/// reads a section runs inside the proof guest too, so its guest has to bake that section in,
/// or its absence, and its predicate then commits to it. Because each guest bakes only its own
/// section, adding a section for a later spec leaves every earlier spec's guest unchanged.
///
/// Every section is optional. A spec whose section is missing keeps the values the chain
/// already has, so a network only needs one to change them. Unknown sections are ignored, so a
/// binary that predates a spec still reads a file that configures it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmRuntimeParams {
    /// Values for spec 2, which installs them when it takes over from an earlier spec. Without
    /// them, spec 2 keeps the chain's confirmation depths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_v2: Option<SpecV2Params>,
}

/// The section of [`AsmRuntimeParams`] that spec 2 reads.
///
/// Spec 2's guest bakes it in as an SSZ `Option`, so a file without the section is baked in
/// too. That encoding is part of what the guest's predicate commits to and cannot change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SpecV2Params {
    /// Confirmation depths spec 2 writes into the administration state, replacing the ones the
    /// chain started with.
    pub confirmation_depths: ConfirmationDepths,
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};

    use super::*;

    #[test]
    fn spec_v2_section_encodes_each_depth_as_a_little_endian_u16_in_field_order() {
        let section = SpecV2Params {
            confirmation_depths: ConfirmationDepths {
                strata_admin_multisig_update: 1,
                strata_seq_manager_multisig_update: 2,
                alpen_admin_multisig_update: 3,
                strata_security_council_multisig_update: 4,
                operator_update: 5,
                sequencer_update: 6,
                ol_stf_vk_update: 7,
                asm_stf_vk_update: 8,
                ee_stf_vk_update: 9,
                defcon3: 10,
                safe_harbor_address_update: 0x0102,
            },
        };

        let bytes = section.as_ssz_bytes();
        assert_eq!(
            bytes,
            [
                1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 0x02, 0x01
            ]
        );
        assert_eq!(SpecV2Params::from_ssz_bytes(&bytes), Ok(section.clone()));

        let baked = Some(section).as_ssz_bytes();
        assert_eq!(baked[0], 1);
        assert_eq!(baked[1..], bytes);
    }

    #[test]
    fn missing_spec_v2_section_encodes_as_the_none_selector() {
        let bytes = None::<SpecV2Params>.as_ssz_bytes();
        assert_eq!(bytes, [0]);
        assert_eq!(Option::<SpecV2Params>::from_ssz_bytes(&bytes), Ok(None));
    }
}
