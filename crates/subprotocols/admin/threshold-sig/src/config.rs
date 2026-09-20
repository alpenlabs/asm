//! Signer configuration for the administration threshold scheme.

use std::{collections::HashSet, num::NonZero};

use bitcoin::{Address, address::NetworkUnchecked};
use serde::{Deserialize, Serialize, de::Error as DeError};
use ssz::DecodeError;
use ssz_primitives::FixedBytes;
use thiserror::Error;

use crate::{
    address::P2wpkhAddress,
    errors::ThresholdSignatureError,
    ssz_bridge::{SszContainer, impl_ssz_via_container},
    ssz_generated::ssz::threshold::{ThresholdConfigSsz, ThresholdConfigUpdateSsz},
};

/// Maximum number of signers allowed in a threshold configuration.
///
/// A signer identifies itself by a `u8` index into the signer list, so no more than 256
/// signers are addressable.
pub const MAX_SIGNERS: usize = 256;

/// Configuration for a threshold signature authority.
///
/// Defines who may sign (`signers`) and how many of them must (`threshold`). The threshold
/// is a `NonZero<u8>` so that a configuration no one can satisfy cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdConfig {
    /// Addresses of all authorized signers.
    signers: Vec<P2wpkhAddress>,
    /// Minimum number of signatures required (always >= 1).
    threshold: NonZero<u8>,
}

impl ThresholdConfig {
    /// Creates a new threshold configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdSignatureError::DuplicateAddMember`] if `signers` repeats a member,
    /// [`ThresholdSignatureError::TooManySigners`] if it holds more than [`MAX_SIGNERS`],
    /// and [`ThresholdSignatureError::InvalidThreshold`] if `threshold` exceeds the number
    /// of signers.
    pub fn try_new(
        signers: Vec<P2wpkhAddress>,
        threshold: NonZero<u8>,
    ) -> Result<Self, ThresholdSignatureError> {
        let mut config = ThresholdConfig {
            signers: vec![],
            threshold,
        };
        let update = ThresholdConfigUpdate::try_new(signers, vec![], threshold)?;
        config.apply_update(&update)?;
        Ok(config)
    }

    /// Returns the authorized signer addresses.
    pub fn signers(&self) -> &[P2wpkhAddress] {
        &self.signers
    }

    /// Returns the number of signatures required.
    pub fn threshold(&self) -> u8 {
        self.threshold.get()
    }

    /// Returns the number of authorized signers.
    pub fn len(&self) -> usize {
        self.signers.len()
    }

    /// Returns whether there are no authorized signers.
    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }

    /// Checks whether an update can be applied to this configuration.
    ///
    /// [`Self::apply_update`] calls this itself, so callers only need it for dry runs.
    pub fn validate_update(
        &self,
        update: &ThresholdConfigUpdate,
    ) -> Result<(), ThresholdSignatureError> {
        let members_to_add: HashSet<&P2wpkhAddress> = update.add_members().iter().collect();
        let members_to_remove: HashSet<&P2wpkhAddress> = update.remove_members().iter().collect();

        if members_to_add.len() != update.add_members().len() {
            return Err(ThresholdSignatureError::DuplicateAddMember);
        }

        if members_to_remove.len() != update.remove_members().len() {
            return Err(ThresholdSignatureError::DuplicateRemoveMember);
        }

        if members_to_add.iter().any(|m| self.signers.contains(m)) {
            return Err(ThresholdSignatureError::MemberAlreadyExists);
        }

        for member_to_remove in update.remove_members() {
            if !self.signers.contains(member_to_remove) {
                return Err(ThresholdSignatureError::MemberNotFound);
            }
        }

        let updated_size =
            self.signers.len() + update.add_members().len() - update.remove_members().len();

        // This is the single chokepoint for every construction, mutation and decode path
        // (`try_new`, `apply_update` and SSZ decode), so enforcing the bound here is what
        // guarantees a `ThresholdConfig` never holds more than `MAX_SIGNERS` signers.
        if updated_size > MAX_SIGNERS {
            return Err(ThresholdSignatureError::TooManySigners {
                count: updated_size,
                max: MAX_SIGNERS,
            });
        }

        if (update.new_threshold().get() as usize) > updated_size {
            return Err(ThresholdSignatureError::InvalidThreshold {
                threshold: update.new_threshold().get(),
                total_signers: updated_size,
            });
        }

        Ok(())
    }

    /// Applies an update to this configuration.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::validate_update`] rejects; the configuration is left
    /// untouched in that case.
    pub fn apply_update(
        &mut self,
        update: &ThresholdConfigUpdate,
    ) -> Result<(), ThresholdSignatureError> {
        self.validate_update(update)?;

        self.signers
            .retain(|signer| !update.remove_members().contains(signer));
        self.signers.extend_from_slice(update.add_members());
        self.threshold = update.new_threshold();

        Ok(())
    }
}

// The schema models `signers` as a `List[Bytes20, MAX_SIGNERS]`: raw witness programs rather
// than the wrapper, so the generated container needs nothing from this crate.
impl SszContainer for ThresholdConfig {
    type Container = ThresholdConfigSsz;

    fn to_container(&self) -> Self::Container {
        // Cannot fail: `validate_update` gates every construction and mutation path, and it
        // rejects more than `MAX_SIGNERS` signers.
        let signers = self
            .signers
            .iter()
            .map(|signer| FixedBytes(signer.to_byte_array()))
            .collect::<Vec<_>>()
            .try_into()
            .expect("signer count is within MAX_SIGNERS");

        ThresholdConfigSsz {
            signers,
            threshold: self.threshold.get(),
        }
    }

    fn from_container(container: Self::Container) -> Result<Self, DecodeError> {
        let signers = decode_signers(container.signers.iter());
        let threshold = NonZero::new(container.threshold)
            .ok_or_else(|| DecodeError::BytesInvalid("threshold must be non-zero".into()))?;

        // Re-applies the same invariants, so a decoded config is indistinguishable from a
        // constructed one.
        Self::try_new(signers, threshold).map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl_ssz_via_container!(ThresholdConfig);

/// The parameter-file form of a [`ThresholdConfig`].
///
/// Signers are written as Bitcoin addresses so an operator can paste back exactly what their
/// hardware wallet displayed. Each one is checked to be P2WPKH on the way in, and the set as
/// a whole is checked against [`ThresholdConfig::try_new`], so
/// [`Self::to_threshold_config`] cannot fail.
///
/// The address is kept as written, prefix and all, so the file round-trips. That prefix is
/// not part of a signer's identity, and whether it matches the network the chain runs on is
/// a question about the parameter file as a whole rather than about any one config.
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
        config.resolve()?;
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
    /// Never for a value that exists: every constructor runs `resolve` first, so a
    /// configuration that could not resolve was never built.
    pub fn to_threshold_config(&self) -> ThresholdConfig {
        self.resolve()
            .expect("signer set was resolved when the configuration was built")
    }

    /// The validation every constructor runs, and the conversion it proves is safe.
    fn resolve(&self) -> Result<ThresholdConfig, InvalidThresholdConfig> {
        let signers = self
            .signers
            .iter()
            .enumerate()
            .map(|(index, address)| {
                P2wpkhAddress::try_from_address(address)
                    .map_err(|_| InvalidThresholdConfig::Signer { index })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ThresholdConfig::try_new(signers, self.threshold)?)
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

/// A change to a [`ThresholdConfig`]: members to add, members to drop, and the threshold
/// that applies once both have been taken into account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdConfigUpdate {
    /// Signer addresses to add.
    add_members: Vec<P2wpkhAddress>,
    /// Signer addresses to remove.
    remove_members: Vec<P2wpkhAddress>,
    /// Minimum number of signatures required (always >= 1).
    new_threshold: NonZero<u8>,
}

impl ThresholdConfigUpdate {
    /// Creates a new threshold configuration update.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdSignatureError::TooManySigners`] if either list holds more than
    /// [`MAX_SIGNERS`] members. The lists are bounded independently because each encodes as
    /// its own `List[_, MAX_SIGNERS]`; without the check an oversized update would panic
    /// when encoded.
    pub fn try_new(
        add_members: Vec<P2wpkhAddress>,
        remove_members: Vec<P2wpkhAddress>,
        new_threshold: NonZero<u8>,
    ) -> Result<Self, ThresholdSignatureError> {
        for list in [&add_members, &remove_members] {
            if list.len() > MAX_SIGNERS {
                return Err(ThresholdSignatureError::TooManySigners {
                    count: list.len(),
                    max: MAX_SIGNERS,
                });
            }
        }
        Ok(Self {
            add_members,
            remove_members,
            new_threshold,
        })
    }

    /// Returns the signer addresses to add.
    pub fn add_members(&self) -> &[P2wpkhAddress] {
        &self.add_members
    }

    /// Returns the signer addresses to remove.
    pub fn remove_members(&self) -> &[P2wpkhAddress] {
        &self.remove_members
    }

    /// Returns the threshold that applies after the update.
    pub fn new_threshold(&self) -> NonZero<u8> {
        self.new_threshold
    }

    /// Consumes the update and returns its parts.
    pub fn into_inner(self) -> (Vec<P2wpkhAddress>, Vec<P2wpkhAddress>, NonZero<u8>) {
        (self.add_members, self.remove_members, self.new_threshold)
    }
}

impl SszContainer for ThresholdConfigUpdate {
    type Container = ThresholdConfigUpdateSsz;

    fn to_container(&self) -> Self::Container {
        // Cannot fail: `try_new` bounds each member list to `MAX_SIGNERS`.
        let to_list = |signers: &[P2wpkhAddress]| {
            signers
                .iter()
                .map(|signer| FixedBytes(signer.to_byte_array()))
                .collect::<Vec<_>>()
                .try_into()
                .expect("member list is within MAX_SIGNERS")
        };

        ThresholdConfigUpdateSsz {
            add_members: to_list(&self.add_members),
            remove_members: to_list(&self.remove_members),
            new_threshold: self.new_threshold.get(),
        }
    }

    fn from_container(container: Self::Container) -> Result<Self, DecodeError> {
        let add_members = decode_signers(container.add_members.iter());
        let remove_members = decode_signers(container.remove_members.iter());
        let new_threshold = NonZero::new(container.new_threshold)
            .ok_or_else(|| DecodeError::BytesInvalid("threshold must be non-zero".into()))?;

        // Cannot fail: each container list is bounded to `MAX_SIGNERS`, which is the bound
        // `try_new` checks.
        Self::try_new(add_members, remove_members, new_threshold)
            .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl_ssz_via_container!(ThresholdConfigUpdate);

/// Converts a container's raw witness programs back into signer addresses.
///
/// This is infallible: every 20-byte value is a well-formed P2WPKH program. Whether anyone
/// holds the key behind it is settled at verification time, not at decode time.
fn decode_signers<'a>(signers: impl Iterator<Item = &'a FixedBytes<20>>) -> Vec<P2wpkhAddress> {
    signers
        .map(|signer| P2wpkhAddress::from_byte_array(signer.0))
        .collect()
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use arbitrary::{Arbitrary, Result, Unstructured};

    use super::*;

    impl<'a> Arbitrary<'a> for ThresholdConfig {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            // Small signer lists keep generated values cheap and well inside MAX_SIGNERS.
            let num_signers: usize = u.int_in_range(1..=4)?;
            let signers: Vec<P2wpkhAddress> = (0..num_signers)
                .map(|_| P2wpkhAddress::arbitrary(u))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if signers.is_empty() {
                return Err(arbitrary::Error::IncorrectFormat);
            }

            let threshold_u8 = u.int_in_range(1..=(signers.len() as u8))?;
            let threshold = NonZero::new(threshold_u8).expect("threshold is at least 1");

            Self::try_new(signers, threshold).map_err(|_| arbitrary::Error::IncorrectFormat)
        }
    }

    impl UncheckedThresholdConfig {
        /// Generates a configuration whose signers are all addresses on `network`.
        ///
        /// [`Arbitrary`] picks the network itself, which is fine for a standalone value but
        /// not when the config has to agree with a network chosen elsewhere.
        pub fn arbitrary_for_network(
            u: &mut Unstructured<'_>,
            network: bitcoin::Network,
        ) -> Result<Self> {
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

    impl<'a> Arbitrary<'a> for UncheckedThresholdConfig {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            let networks = [
                bitcoin::Network::Bitcoin,
                bitcoin::Network::Testnet,
                bitcoin::Network::Signet,
                bitcoin::Network::Regtest,
            ];
            let network = *u.choose(&networks)?;
            Self::arbitrary_for_network(u, network)
        }
    }

    impl<'a> Arbitrary<'a> for ThresholdConfigUpdate {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            let gen_members = |u: &mut Unstructured<'a>| {
                let count = u.int_in_range(0..=4)?;
                (0..count)
                    .map(|_| P2wpkhAddress::arbitrary(u))
                    .collect::<Result<Vec<_>>>()
            };
            let add_members = gen_members(u)?;
            let remove_members = gen_members(u)?;
            let max_threshold = add_members.len().max(1) as u8;
            let threshold_u8 = u.int_in_range(1..=max_threshold)?;
            let new_threshold = NonZero::new(threshold_u8).expect("threshold is at least 1");

            Self::try_new(add_members, remove_members, new_threshold)
                .map_err(|_| arbitrary::Error::IncorrectFormat)
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use ssz::{Decode, Encode};

    use super::*;

    /// Builds a distinct signer address from a wide seed, so more than 255 unique
    /// addresses are reachable.
    fn signer_n(i: u32) -> P2wpkhAddress {
        let mut program = [0u8; 20];
        program[16..20].copy_from_slice(&(i + 1).to_be_bytes());
        P2wpkhAddress::from_byte_array(program)
    }

    fn signer(seed: u8) -> P2wpkhAddress {
        signer_n(seed as u32)
    }

    fn nonzero(value: u8) -> NonZero<u8> {
        NonZero::new(value).expect("test threshold is non-zero")
    }

    #[test]
    fn try_new_keeps_signers_and_threshold() {
        let signers = vec![signer(1), signer(2), signer(3)];
        let config = ThresholdConfig::try_new(signers, nonzero(2)).unwrap();

        assert_eq!(config.len(), 3);
        assert_eq!(config.threshold(), 2);
    }

    #[test]
    fn try_new_rejects_more_than_max_signers() {
        let signers: Vec<_> = (0..=MAX_SIGNERS as u32).map(signer_n).collect();
        assert!(matches!(
            ThresholdConfig::try_new(signers, nonzero(1)),
            Err(ThresholdSignatureError::TooManySigners { .. })
        ));
    }

    #[test]
    fn try_new_rejects_duplicate_signers() {
        let signers = vec![signer(1), signer(1)];
        assert!(matches!(
            ThresholdConfig::try_new(signers, nonzero(1)),
            Err(ThresholdSignatureError::DuplicateAddMember)
        ));
    }

    #[test]
    fn try_new_rejects_threshold_above_signer_count() {
        let signers = vec![signer(1), signer(2)];
        assert!(matches!(
            ThresholdConfig::try_new(signers, nonzero(3)),
            Err(ThresholdSignatureError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn update_rejects_more_than_max_signers_per_list() {
        let oversized: Vec<_> = (0..=MAX_SIGNERS as u32).map(signer_n).collect();

        assert!(matches!(
            ThresholdConfigUpdate::try_new(oversized.clone(), vec![], nonzero(1)),
            Err(ThresholdSignatureError::TooManySigners { .. })
        ));
        assert!(matches!(
            ThresholdConfigUpdate::try_new(vec![], oversized, nonzero(1)),
            Err(ThresholdSignatureError::TooManySigners { .. })
        ));
    }

    #[test]
    fn apply_update_adds_a_member() {
        let mut config = ThresholdConfig::try_new(vec![signer(1), signer(2)], nonzero(2)).unwrap();

        let update = ThresholdConfigUpdate::try_new(vec![signer(3)], vec![], nonzero(2)).unwrap();
        config.apply_update(&update).unwrap();

        assert_eq!(config.len(), 3);
    }

    #[test]
    fn apply_update_removes_a_member() {
        let s2 = signer(2);
        let mut config =
            ThresholdConfig::try_new(vec![signer(1), s2, signer(3)], nonzero(2)).unwrap();

        let update = ThresholdConfigUpdate::try_new(vec![], vec![s2], nonzero(2)).unwrap();
        config.apply_update(&update).unwrap();

        assert_eq!(config.len(), 2);
        assert!(!config.signers().contains(&s2));
    }

    #[test]
    fn apply_update_rejects_an_unknown_member_removal() {
        let mut config = ThresholdConfig::try_new(vec![signer(1)], nonzero(1)).unwrap();
        let update = ThresholdConfigUpdate::try_new(vec![], vec![signer(9)], nonzero(1)).unwrap();

        assert_eq!(
            config.apply_update(&update),
            Err(ThresholdSignatureError::MemberNotFound)
        );
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn apply_update_rejects_an_existing_member() {
        let s1 = signer(1);
        let mut config = ThresholdConfig::try_new(vec![s1], nonzero(1)).unwrap();
        let update = ThresholdConfigUpdate::try_new(vec![s1], vec![], nonzero(1)).unwrap();

        assert_eq!(
            config.apply_update(&update),
            Err(ThresholdSignatureError::MemberAlreadyExists)
        );
    }

    #[test]
    fn apply_update_rejects_duplicates_within_a_list() {
        let mut config = ThresholdConfig::try_new(vec![signer(1)], nonzero(1)).unwrap();
        let s2 = signer(2);

        let dup_add = ThresholdConfigUpdate::try_new(vec![s2, s2], vec![], nonzero(1)).unwrap();
        assert_eq!(
            config.apply_update(&dup_add),
            Err(ThresholdSignatureError::DuplicateAddMember)
        );

        let s1 = signer(1);
        let dup_remove = ThresholdConfigUpdate::try_new(vec![], vec![s1, s1], nonzero(1)).unwrap();
        assert_eq!(
            config.apply_update(&dup_remove),
            Err(ThresholdSignatureError::DuplicateRemoveMember)
        );
    }

    #[test]
    fn config_ssz_byte_layout() {
        let signers = vec![signer(1), signer(2), signer(3)];
        let config = ThresholdConfig::try_new(signers.clone(), nonzero(2)).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&5u32.to_le_bytes()); // offset to signers
        expected.push(2); // threshold
        for signer in &signers {
            expected.extend_from_slice(&signer.to_byte_array());
        }

        assert_eq!(config.as_ssz_bytes(), expected);
        assert_eq!(config.ssz_bytes_len(), expected.len());
        assert_eq!(ThresholdConfig::from_ssz_bytes(&expected).unwrap(), config);
    }

    #[test]
    fn update_ssz_byte_layout() {
        let add = vec![signer(1), signer(2)];
        let remove = vec![signer(3)];
        let update =
            ThresholdConfigUpdate::try_new(add.clone(), remove.clone(), nonzero(2)).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&9u32.to_le_bytes()); // offset to add_members
        expected.extend_from_slice(&(9u32 + 2 * 20).to_le_bytes()); // offset to remove_members
        expected.push(2); // new_threshold
        for signer in add.iter().chain(&remove) {
            expected.extend_from_slice(&signer.to_byte_array());
        }

        assert_eq!(update.as_ssz_bytes(), expected);
        assert_eq!(update.ssz_bytes_len(), expected.len());
        assert_eq!(
            ThresholdConfigUpdate::from_ssz_bytes(&expected).unwrap(),
            update
        );
    }

    #[test]
    fn empty_member_lists_encode_to_the_fixed_part_alone() {
        let update = ThresholdConfigUpdate::try_new(vec![], vec![], nonzero(1)).unwrap();
        let encoded = update.as_ssz_bytes();

        assert_eq!(encoded.len(), 9);
        assert_eq!(
            ThresholdConfigUpdate::from_ssz_bytes(&encoded).unwrap(),
            update
        );
    }

    #[test]
    fn config_ssz_rejects_a_zero_threshold() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&signer(1).to_byte_array());

        assert!(ThresholdConfig::from_ssz_bytes(&bytes).is_err());
    }

    /// Any 20-byte value is a well-formed witness program, so decoding accepts a signer
    /// nobody holds the key for. Such a signer simply never produces a verifying signature;
    /// there is no curve-point check to fall back on the way there was for public keys.
    #[test]
    fn config_ssz_accepts_any_witness_program() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0u8; 20]);

        let config = ThresholdConfig::from_ssz_bytes(&bytes).expect("any program decodes");
        assert_eq!(
            config.signers(),
            [P2wpkhAddress::from_byte_array([0u8; 20])]
        );
    }

    #[test]
    fn config_ssz_rejects_a_truncated_signer() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&signer(1).to_byte_array()[..19]);

        assert!(ThresholdConfig::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn config_ssz_rejects_a_misplaced_offset() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&6u32.to_le_bytes()); // should be 5
        bytes.push(1);
        bytes.extend_from_slice(&signer(1).to_byte_array());

        assert!(ThresholdConfig::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn update_ssz_rejects_decreasing_offsets() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&9u32.to_le_bytes());
        bytes.extend_from_slice(&8u32.to_le_bytes()); // points before add_members
        bytes.push(1);

        assert!(ThresholdConfigUpdate::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn update_ssz_rejects_an_out_of_bounds_offset() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&9u32.to_le_bytes());
        bytes.extend_from_slice(&99u32.to_le_bytes()); // past the end
        bytes.push(1);

        assert!(ThresholdConfigUpdate::from_ssz_bytes(&bytes).is_err());
    }

    /// Produces a valid config with distinct signers and an in-range threshold.
    fn arb_threshold_config() -> impl Strategy<Value = ThresholdConfig> {
        (1usize..=8)
            .prop_flat_map(|n| (Just(n), 1u8..=(n as u8)))
            .prop_map(|(n, threshold)| {
                let signers = (0..n as u32).map(signer_n).collect::<Vec<_>>();
                ThresholdConfig::try_new(signers, nonzero(threshold))
                    .expect("signers and threshold are valid")
            })
    }

    /// Produces an update with disjoint add and remove lists.
    fn arb_threshold_update() -> impl Strategy<Value = ThresholdConfigUpdate> {
        (0usize..=4, 0usize..=4).prop_map(|(add, remove)| {
            let add_members = (0..add as u32).map(signer_n).collect::<Vec<_>>();
            let remove_members = (100..100 + remove as u32).map(signer_n).collect::<Vec<_>>();
            ThresholdConfigUpdate::try_new(add_members, remove_members, nonzero(1))
                .expect("update is within bounds")
        })
    }

    proptest! {
        #[test]
        fn config_ssz_roundtrips(config in arb_threshold_config()) {
            let encoded = config.as_ssz_bytes();
            prop_assert_eq!(encoded.len(), config.ssz_bytes_len());
            prop_assert_eq!(ThresholdConfig::from_ssz_bytes(&encoded).unwrap(), config);
        }

        #[test]
        fn update_ssz_roundtrips(update in arb_threshold_update()) {
            let encoded = update.as_ssz_bytes();
            prop_assert_eq!(encoded.len(), update.ssz_bytes_len());
            prop_assert_eq!(ThresholdConfigUpdate::from_ssz_bytes(&encoded).unwrap(), update);
        }
    }
}
