use std::num::NonZero;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use strata_asm_admin_threshold_sig::{ThresholdConfig, UncheckedThresholdConfig};

use crate::{ConfirmationDepths, Role};

/// Initialization configuration for the administration subprotocol, holding each role's
/// signer set as it is written in the parameter file.
///
/// Signers are named by Bitcoin address here and by witness program in the state the
/// subprotocol builds from this; [`Self::get_all_authorities`] is the conversion.
///
/// Design choice: Uses individual named fields rather than `Vec<(Role, ThresholdConfig)>`
/// to ensure structural completeness - the compiler guarantees all config fields are
/// provided when constructing this struct. However, it does NOT prevent logical errors
/// like using the same config for multiple roles or mismatched role-field assignments.
/// The benefit is avoiding missing fields at compile-time rather than runtime validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdministrationInitConfig {
    /// Signers for [StrataAdministrator](Role::StrataAdministrator).
    pub strata_administrator: UncheckedThresholdConfig,

    /// Signers for [StrataSequencerManager](Role::StrataSequencerManager).
    pub strata_sequencer_manager: UncheckedThresholdConfig,

    /// Signers for [AlpenAdministrator](Role::AlpenAdministrator).
    pub alpen_administrator: UncheckedThresholdConfig,

    /// Signers for [StrataSecurityCouncil](Role::StrataSecurityCouncil).
    pub strata_security_council: UncheckedThresholdConfig,

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
        strata_administrator: UncheckedThresholdConfig,
        strata_sequencer_manager: UncheckedThresholdConfig,
        alpen_administrator: UncheckedThresholdConfig,
        strata_security_council: UncheckedThresholdConfig,
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

    /// Borrows a role's signer set as the parameter file wrote it.
    pub fn get_config(&self, role: Role) -> &UncheckedThresholdConfig {
        match role {
            Role::StrataAdministrator => &self.strata_administrator,
            Role::StrataSequencerManager => &self.strata_sequencer_manager,
            Role::AlpenAdministrator => &self.alpen_administrator,
            Role::StrataSecurityCouncil => &self.strata_security_council,
        }
    }

    /// Finds the first signer whose address was not written for `network`.
    ///
    /// Signers are named by address, so an operator writes each one with a network prefix.
    /// The prefix plays no part in authorization, which is why it is not stored, but a
    /// prefix that disagrees with the chain means the file and the chain were prepared
    /// against different networks and the operator should look again.
    pub fn find_signer_not_on_network(&self, network: Network) -> Option<(Role, usize)> {
        [
            (Role::StrataAdministrator, &self.strata_administrator),
            (Role::StrataSequencerManager, &self.strata_sequencer_manager),
            (Role::AlpenAdministrator, &self.alpen_administrator),
            (Role::StrataSecurityCouncil, &self.strata_security_council),
        ]
        .into_iter()
        .find_map(|(role, config)| {
            config
                .signers()
                .iter()
                .position(|address| !address.is_valid_for_network(network))
                .map(|index| (role, index))
        })
    }

    /// Resolves every role's signer addresses into the configuration its authority holds.
    pub fn get_all_authorities(&self) -> Vec<(Role, ThresholdConfig)> {
        vec![
            (
                Role::StrataAdministrator,
                self.strata_administrator.to_threshold_config(),
            ),
            (
                Role::StrataSequencerManager,
                self.strata_sequencer_manager.to_threshold_config(),
            ),
            (
                Role::AlpenAdministrator,
                self.alpen_administrator.to_threshold_config(),
            ),
            (
                Role::StrataSecurityCouncil,
                self.strata_security_council.to_threshold_config(),
            ),
        ]
    }
}

#[cfg(feature = "arbitrary")]
impl AdministrationInitConfig {
    /// Generates a configuration whose signers are all addresses on `network`.
    ///
    /// [`Arbitrary`] picks the network itself, which leaves each role on a different one.
    /// Callers that already have a network need this instead.
    pub fn arbitrary_for_network(
        u: &mut Unstructured<'_>,
        network: Network,
    ) -> arbitrary::Result<Self> {
        // Generate a valid NonZero<u8> by mapping [0, 255) to [1, 256) via saturating add.
        let raw: u8 = u.arbitrary()?;
        let max_seqno_gap = NonZero::new(raw.saturating_add(1))
            .expect("saturating_add(1) on u8 always produces a non-zero value");

        Ok(Self {
            strata_administrator: UncheckedThresholdConfig::arbitrary_for_network(u, network)?,
            strata_sequencer_manager: UncheckedThresholdConfig::arbitrary_for_network(u, network)?,
            alpen_administrator: UncheckedThresholdConfig::arbitrary_for_network(u, network)?,
            strata_security_council: UncheckedThresholdConfig::arbitrary_for_network(u, network)?,
            confirmation_depths: u.arbitrary()?,
            max_seqno_gap,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AdministrationInitConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let networks = [
            Network::Bitcoin,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ];
        let network = *u.choose(&networks)?;
        Self::arbitrary_for_network(u, network)
    }
}
