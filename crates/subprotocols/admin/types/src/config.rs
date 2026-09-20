use std::num::NonZero;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bitcoin::{Address, Network, address::NetworkUnchecked};
use serde::{Deserialize, Serialize, de::Error as DeError};
use strata_asm_admin_threshold_sig::{P2wpkhAddress, ThresholdConfig, ThresholdSignatureError};
use thiserror::Error;

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

/// The parameter-file form of a [`ThresholdConfig`].
///
/// Signers are written as Bitcoin addresses so an operator can paste back exactly what their
/// hardware wallet displayed. Each one is checked to be P2WPKH on the way in, and the set as
/// a whole is checked against [`ThresholdConfig::try_new`], so
/// [`Self::to_threshold_config`] cannot fail.
///
/// The address is kept as written, prefix and all, so the file round-trips. That prefix is
/// not part of a signer's identity, and whether it matches the network the chain runs on is
/// a question about the parameter file as a whole rather than about any one config, which is
/// why [`AdministrationInitConfig::find_signer_not_on_network`] asks it instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UncheckedThresholdConfig {
    /// Addresses of all authorized signers, each one P2WPKH.
    signers: Vec<Address<NetworkUnchecked>>,
    /// Minimum number of signatures required (always >= 1).
    threshold: NonZero<u8>,
}

impl UncheckedThresholdConfig {
    /// Creates a configuration from signer addresses.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidThresholdConfig::Signer`] if an address is not P2WPKH, and
    /// [`InvalidThresholdConfig::Config`] if the signer set is not one a
    /// [`ThresholdConfig`] can hold.
    pub fn try_new(
        signers: Vec<Address<NetworkUnchecked>>,
        threshold: NonZero<u8>,
    ) -> Result<Self, InvalidThresholdConfig> {
        let config = Self { signers, threshold };
        ThresholdConfig::try_from(&config)?;
        Ok(config)
    }

    /// Returns the configured signer addresses, as written.
    pub fn signers(&self) -> &[Address<NetworkUnchecked>] {
        &self.signers
    }

    /// Returns the number of signatures required.
    pub fn threshold(&self) -> NonZero<u8> {
        self.threshold
    }

    /// Resolves the addresses into the [`ThresholdConfig`] the chain stores.
    ///
    /// # Panics
    ///
    /// Never for a value that exists: every constructor runs the conversion first, so a
    /// configuration that could not resolve was never built.
    pub fn to_threshold_config(&self) -> ThresholdConfig {
        ThresholdConfig::try_from(self)
            .expect("signer set was resolved when the configuration was built")
    }
}

/// Resolves a parameter-file configuration into the one the chain stores.
///
/// This is the validation [`UncheckedThresholdConfig::try_new`] runs, which is why
/// [`UncheckedThresholdConfig::to_threshold_config`] can be infallible.
impl TryFrom<&UncheckedThresholdConfig> for ThresholdConfig {
    type Error = InvalidThresholdConfig;

    fn try_from(config: &UncheckedThresholdConfig) -> Result<Self, Self::Error> {
        let signers = config
            .signers
            .iter()
            .enumerate()
            .map(|(index, address)| {
                P2wpkhAddress::try_from_address(address)
                    .map_err(|_| InvalidThresholdConfig::Signer { index })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ThresholdConfig::try_new(signers, config.threshold)?)
    }
}

/// [`Deserialize`] is implemented by hand so that decoded values go through
/// [`UncheckedThresholdConfig::try_new`] and satisfy the same invariants as constructed ones.
impl<'de> Deserialize<'de> for UncheckedThresholdConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            signers: Vec<Address<NetworkUnchecked>>,
            threshold: NonZero<u8>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::try_new(raw.signers, raw.threshold).map_err(DeError::custom)
    }
}

/// Reasons a parameter-file threshold configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidThresholdConfig {
    /// A configured signer is not a P2WPKH address.
    #[error("signer at index {index} is not a P2WPKH address")]
    Signer {
        /// Position of the signer in the configured list.
        index: usize,
    },

    /// The signer set is not one a [`ThresholdConfig`] can hold.
    #[error(transparent)]
    Config(#[from] ThresholdSignatureError),
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

// TODO: this network choice is duplicated in `UncheckedThresholdConfig::arbitrary` below.
// Now that both live in this file, they should share one helper that picks a network.
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

#[cfg(feature = "arbitrary")]
impl UncheckedThresholdConfig {
    /// Generates a configuration whose signers are all addresses on `network`.
    ///
    /// [`Arbitrary`] picks the network itself, which is fine for a standalone value but not
    /// when the config has to agree with a network chosen elsewhere.
    pub fn arbitrary_for_network(
        u: &mut Unstructured<'_>,
        network: Network,
    ) -> arbitrary::Result<Self> {
        let config = ThresholdConfig::arbitrary(u)?;
        let signers = config
            .signers()
            .iter()
            .map(|signer| signer.to_address(network).into_unchecked())
            .collect();

        Self::try_new(
            signers,
            NonZero::new(config.threshold()).expect("threshold is at least 1"),
        )
        .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for UncheckedThresholdConfig {
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
