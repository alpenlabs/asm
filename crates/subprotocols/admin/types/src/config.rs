use std::num::NonZero;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use strata_asm_admin_threshold_sig::ThresholdConfig;

use crate::{ConfirmationDepths, Role};

/// Initialization configuration for the administration subprotocol, containing [`ThresholdConfig`]
/// for each role.
///
/// Design choice: Uses individual named fields rather than `Vec<(Role, ThresholdConfig)>`
/// to ensure structural completeness - the compiler guarantees all config fields are
/// provided when constructing this struct. However, it does NOT prevent logical errors
/// like using the same config for multiple roles or mismatched role-field assignments.
/// The benefit is avoiding missing fields at compile-time rather than runtime validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdministrationInitConfig {
    /// ThresholdConfig for [StrataAdministrator](Role::StrataAdministrator).
    pub strata_administrator: ThresholdConfig,

    /// ThresholdConfig for [StrataSequencerManager](Role::StrataSequencerManager).
    pub strata_sequencer_manager: ThresholdConfig,

    /// ThresholdConfig for [AlpenAdministrator](Role::AlpenAdministrator).
    pub alpen_administrator: ThresholdConfig,

    /// ThresholdConfig for [StrataSecurityCouncil](Role::StrataSecurityCouncil).
    pub strata_security_council: ThresholdConfig,

    /// Per-variant confirmation depths (CD) for queued admin updates.
    pub confirmation_depths: ConfirmationDepths,

    /// Maximum allowed gap between consecutive sequence numbers for a given authority.
    ///
    /// A payload with `seqno > last_seqno + max_seqno_gap` is rejected. This prevents
    /// excessively large jumps in sequence numbers while still allowing non-sequential usage.
    pub max_seqno_gap: NonZero<u8>,
}

impl AdministrationInitConfig {
    pub fn new(
        strata_administrator: ThresholdConfig,
        strata_sequencer_manager: ThresholdConfig,
        alpen_administrator: ThresholdConfig,
        strata_security_council: ThresholdConfig,
        confirmation_depths: ConfirmationDepths,
        max_seqno_gap: NonZero<u8>,
    ) -> Self {
        Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            strata_security_council,
            confirmation_depths,
            max_seqno_gap,
        }
    }

    pub fn get_config(&self, role: Role) -> &ThresholdConfig {
        match role {
            Role::StrataAdministrator => &self.strata_administrator,
            Role::StrataSequencerManager => &self.strata_sequencer_manager,
            Role::AlpenAdministrator => &self.alpen_administrator,
            Role::StrataSecurityCouncil => &self.strata_security_council,
        }
    }

    pub fn get_all_authorities(self) -> Vec<(Role, ThresholdConfig)> {
        vec![
            (Role::StrataAdministrator, self.strata_administrator),
            (Role::StrataSequencerManager, self.strata_sequencer_manager),
            (Role::AlpenAdministrator, self.alpen_administrator),
            (Role::StrataSecurityCouncil, self.strata_security_council),
        ]
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AdministrationInitConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let strata_administrator = u.arbitrary()?;
        let strata_sequencer_manager = u.arbitrary()?;
        let alpen_administrator = u.arbitrary()?;
        let strata_security_council = u.arbitrary()?;
        let confirmation_depths = u.arbitrary()?;
        // Generate a valid NonZero<u8> by mapping [0, 255) to [1, 256) via saturating add.
        let raw: u8 = u.arbitrary()?;
        let max_seqno_gap = NonZero::new(raw.saturating_add(1))
            .expect("saturating_add(1) on u8 always produces a non-zero value");

        Ok(Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            strata_security_council,
            confirmation_depths,
            max_seqno_gap,
        })
    }
}
