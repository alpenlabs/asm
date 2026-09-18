//! Signer configuration for the administration threshold scheme.

use std::{collections::HashSet, num::NonZero};

use serde::{Deserialize, Serialize, de::Error as DeError};
use ssz::DecodeError;
use ssz_primitives::FixedBytes;

use crate::{
    errors::ThresholdSignatureError,
    keys::CompressedPublicKey,
    ssz_bridge::{SszContainer, impl_ssz_via_container},
    ssz_generated::ssz::threshold::{ThresholdConfigSsz, ThresholdConfigUpdateSsz},
};

/// Maximum number of signers allowed in a threshold configuration.
///
/// A signer identifies itself by a `u8` index into the key list, so no more than 256 signers
/// are addressable.
pub const MAX_SIGNERS: usize = 256;

/// Configuration for a threshold signature authority.
///
/// Defines who may sign (`keys`) and how many of them must (`threshold`). The threshold is a
/// `NonZero<u8>` so that a configuration no one can satisfy cannot be constructed.
///
/// [`Deserialize`] is implemented by hand so that decoded values go through
/// [`Self::try_new`] and satisfy the same invariants as constructed ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThresholdConfig {
    /// Public keys of all authorized signers.
    keys: Vec<CompressedPublicKey>,
    /// Minimum number of signatures required (always >= 1).
    threshold: NonZero<u8>,
}

impl ThresholdConfig {
    /// Creates a new threshold configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ThresholdSignatureError::DuplicateAddMember`] if `keys` repeats a member,
    /// [`ThresholdSignatureError::TooManySigners`] if it holds more than [`MAX_SIGNERS`],
    /// and [`ThresholdSignatureError::InvalidThreshold`] if `threshold` exceeds the number
    /// of keys.
    pub fn try_new(
        keys: Vec<CompressedPublicKey>,
        threshold: NonZero<u8>,
    ) -> Result<Self, ThresholdSignatureError> {
        let mut config = ThresholdConfig {
            keys: vec![],
            threshold,
        };
        let update = ThresholdConfigUpdate::try_new(keys, vec![], threshold)?;
        config.apply_update(&update)?;
        Ok(config)
    }

    /// Returns the authorized signer keys.
    pub fn keys(&self) -> &[CompressedPublicKey] {
        &self.keys
    }

    /// Returns the number of signatures required.
    pub fn threshold(&self) -> u8 {
        self.threshold.get()
    }

    /// Returns the number of authorized signers.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether there are no authorized signers.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Checks whether an update can be applied to this configuration.
    ///
    /// [`Self::apply_update`] calls this itself, so callers only need it for dry runs.
    pub fn validate_update(
        &self,
        update: &ThresholdConfigUpdate,
    ) -> Result<(), ThresholdSignatureError> {
        let members_to_add: HashSet<&CompressedPublicKey> = update.add_members().iter().collect();
        let members_to_remove: HashSet<&CompressedPublicKey> =
            update.remove_members().iter().collect();

        if members_to_add.len() != update.add_members().len() {
            return Err(ThresholdSignatureError::DuplicateAddMember);
        }

        if members_to_remove.len() != update.remove_members().len() {
            return Err(ThresholdSignatureError::DuplicateRemoveMember);
        }

        if members_to_add.iter().any(|m| self.keys.contains(m)) {
            return Err(ThresholdSignatureError::MemberAlreadyExists);
        }

        for member_to_remove in update.remove_members() {
            if !self.keys.contains(member_to_remove) {
                return Err(ThresholdSignatureError::MemberNotFound);
            }
        }

        let updated_size =
            self.keys.len() + update.add_members().len() - update.remove_members().len();

        // This is the single chokepoint for every construction, mutation and decode path
        // (`try_new`, `apply_update`, serde and SSZ decode), so enforcing the bound here is
        // what guarantees a `ThresholdConfig` never holds more than `MAX_SIGNERS` keys.
        if updated_size > MAX_SIGNERS {
            return Err(ThresholdSignatureError::TooManySigners {
                count: updated_size,
                max: MAX_SIGNERS,
            });
        }

        if (update.new_threshold().get() as usize) > updated_size {
            return Err(ThresholdSignatureError::InvalidThreshold {
                threshold: update.new_threshold().get(),
                total_keys: updated_size,
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

        self.keys
            .retain(|key| !update.remove_members().contains(key));
        self.keys.extend_from_slice(update.add_members());
        self.threshold = update.new_threshold();

        Ok(())
    }
}

impl<'de> Deserialize<'de> for ThresholdConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            keys: Vec<CompressedPublicKey>,
            threshold: NonZero<u8>,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::try_new(raw.keys, raw.threshold).map_err(DeError::custom)
    }
}

// The schema models `keys` as a `List[Bytes33, MAX_SIGNERS]`: raw compressed points rather
// than the wrapper, so the generated container needs nothing from this crate. The curve-point
// check the wrapper performs is reapplied in `from_container`.
impl SszContainer for ThresholdConfig {
    type Container = ThresholdConfigSsz;

    fn to_container(&self) -> Self::Container {
        // Cannot fail: `validate_update` gates every construction and mutation path, and it
        // rejects more than `MAX_SIGNERS` keys.
        let keys = self
            .keys
            .iter()
            .map(|key| FixedBytes(key.serialize()))
            .collect::<Vec<_>>()
            .try_into()
            .expect("key count is within MAX_SIGNERS");

        ThresholdConfigSsz {
            keys,
            threshold: self.threshold.get(),
        }
    }

    fn from_container(container: Self::Container) -> Result<Self, DecodeError> {
        let keys = decode_keys(container.keys.iter())?;
        let threshold = NonZero::new(container.threshold)
            .ok_or_else(|| DecodeError::BytesInvalid("threshold must be non-zero".into()))?;

        // Re-applies the same invariants, so a decoded config is indistinguishable from a
        // constructed one.
        Self::try_new(keys, threshold).map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl_ssz_via_container!(ThresholdConfig);

/// A change to a [`ThresholdConfig`]: members to add, members to drop, and the threshold
/// that applies once both have been taken into account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdConfigUpdate {
    /// Public keys to add.
    add_members: Vec<CompressedPublicKey>,
    /// Public keys to remove.
    remove_members: Vec<CompressedPublicKey>,
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
        add_members: Vec<CompressedPublicKey>,
        remove_members: Vec<CompressedPublicKey>,
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

    /// Returns the public keys to add.
    pub fn add_members(&self) -> &[CompressedPublicKey] {
        &self.add_members
    }

    /// Returns the public keys to remove.
    pub fn remove_members(&self) -> &[CompressedPublicKey] {
        &self.remove_members
    }

    /// Returns the threshold that applies after the update.
    pub fn new_threshold(&self) -> NonZero<u8> {
        self.new_threshold
    }

    /// Consumes the update and returns its parts.
    pub fn into_inner(
        self,
    ) -> (
        Vec<CompressedPublicKey>,
        Vec<CompressedPublicKey>,
        NonZero<u8>,
    ) {
        (self.add_members, self.remove_members, self.new_threshold)
    }
}

impl SszContainer for ThresholdConfigUpdate {
    type Container = ThresholdConfigUpdateSsz;

    fn to_container(&self) -> Self::Container {
        // Cannot fail: `try_new` bounds each member list to `MAX_SIGNERS`.
        let to_list = |keys: &[CompressedPublicKey]| {
            keys.iter()
                .map(|key| FixedBytes(key.serialize()))
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
        let add_members = decode_keys(container.add_members.iter())?;
        let remove_members = decode_keys(container.remove_members.iter())?;
        let new_threshold = NonZero::new(container.new_threshold)
            .ok_or_else(|| DecodeError::BytesInvalid("threshold must be non-zero".into()))?;

        // Cannot fail: each container list is bounded to `MAX_SIGNERS`, which is the bound
        // `try_new` checks.
        Self::try_new(add_members, remove_members, new_threshold)
            .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
    }
}

impl_ssz_via_container!(ThresholdConfigUpdate);

/// Converts a container's raw compressed points back into validated keys.
fn decode_keys<'a>(
    keys: impl Iterator<Item = &'a FixedBytes<33>>,
) -> Result<Vec<CompressedPublicKey>, DecodeError> {
    keys.map(|key| CompressedPublicKey::from_slice(&key.0))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| DecodeError::BytesInvalid(err.to_string()))
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use arbitrary::{Arbitrary, Result, Unstructured};

    use super::*;

    impl<'a> Arbitrary<'a> for ThresholdConfig {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            // Small key lists keep generated values cheap and well inside MAX_SIGNERS.
            let num_keys: usize = u.int_in_range(1..=4)?;
            let keys: Vec<CompressedPublicKey> = (0..num_keys)
                .map(|_| CompressedPublicKey::arbitrary(u))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if keys.is_empty() {
                return Err(arbitrary::Error::IncorrectFormat);
            }

            let threshold_u8 = u.int_in_range(1..=(keys.len() as u8))?;
            let threshold = NonZero::new(threshold_u8).expect("threshold is at least 1");

            Self::try_new(keys, threshold).map_err(|_| arbitrary::Error::IncorrectFormat)
        }
    }

    impl<'a> Arbitrary<'a> for ThresholdConfigUpdate {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
            let gen_members = |u: &mut Unstructured<'a>| {
                let count = u.int_in_range(0..=4)?;
                (0..count)
                    .map(|_| CompressedPublicKey::arbitrary(u))
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
    use secp256k1::{PublicKey, SECP256K1, SecretKey};
    use ssz::{Decode, Encode};

    use super::*;

    fn make_key(seed: u8) -> CompressedPublicKey {
        make_key_n(seed as u32)
    }

    /// Builds a distinct key from a wide seed, so more than 255 unique keys are reachable.
    fn make_key_n(i: u32) -> CompressedPublicKey {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[28..32].copy_from_slice(&(i + 1).to_be_bytes());
        let sk = SecretKey::from_slice(&sk_bytes).expect("seed is a valid scalar");
        CompressedPublicKey::from(PublicKey::from_secret_key(SECP256K1, &sk))
    }

    fn nonzero(value: u8) -> NonZero<u8> {
        NonZero::new(value).expect("test threshold is non-zero")
    }

    #[test]
    fn try_new_keeps_keys_and_threshold() {
        let keys = vec![make_key(1), make_key(2), make_key(3)];
        let config = ThresholdConfig::try_new(keys, nonzero(2)).unwrap();

        assert_eq!(config.len(), 3);
        assert_eq!(config.threshold(), 2);
    }

    #[test]
    fn try_new_rejects_more_than_max_signers() {
        let keys: Vec<_> = (0..=MAX_SIGNERS as u32).map(make_key_n).collect();
        assert!(matches!(
            ThresholdConfig::try_new(keys, nonzero(1)),
            Err(ThresholdSignatureError::TooManySigners { .. })
        ));
    }

    #[test]
    fn try_new_rejects_duplicate_keys() {
        let keys = vec![make_key(1), make_key(1)];
        assert!(matches!(
            ThresholdConfig::try_new(keys, nonzero(1)),
            Err(ThresholdSignatureError::DuplicateAddMember)
        ));
    }

    #[test]
    fn try_new_rejects_threshold_above_key_count() {
        let keys = vec![make_key(1), make_key(2)];
        assert!(matches!(
            ThresholdConfig::try_new(keys, nonzero(3)),
            Err(ThresholdSignatureError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn deserialize_rejects_more_than_max_signers() {
        // The validating `Deserialize` routes through `try_new`, so an oversized key list is
        // rejected rather than decoded into a value that later panics when encoded.
        let keys: Vec<_> = (0..=MAX_SIGNERS as u32).map(make_key_n).collect();
        let json = serde_json::json!({ "keys": keys, "threshold": 1 });
        assert!(serde_json::from_value::<ThresholdConfig>(json).is_err());
    }

    #[test]
    fn update_rejects_more_than_max_signers_per_list() {
        let oversized: Vec<_> = (0..=MAX_SIGNERS as u32).map(make_key_n).collect();

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
        let mut config =
            ThresholdConfig::try_new(vec![make_key(1), make_key(2)], nonzero(2)).unwrap();

        let update = ThresholdConfigUpdate::try_new(vec![make_key(3)], vec![], nonzero(2)).unwrap();
        config.apply_update(&update).unwrap();

        assert_eq!(config.len(), 3);
    }

    #[test]
    fn apply_update_removes_a_member() {
        let k2 = make_key(2);
        let mut config =
            ThresholdConfig::try_new(vec![make_key(1), k2, make_key(3)], nonzero(2)).unwrap();

        let update = ThresholdConfigUpdate::try_new(vec![], vec![k2], nonzero(2)).unwrap();
        config.apply_update(&update).unwrap();

        assert_eq!(config.len(), 2);
        assert!(!config.keys().contains(&k2));
    }

    #[test]
    fn apply_update_rejects_an_unknown_member_removal() {
        let mut config = ThresholdConfig::try_new(vec![make_key(1)], nonzero(1)).unwrap();
        let update = ThresholdConfigUpdate::try_new(vec![], vec![make_key(9)], nonzero(1)).unwrap();

        assert_eq!(
            config.apply_update(&update),
            Err(ThresholdSignatureError::MemberNotFound)
        );
        assert_eq!(config.len(), 1);
    }

    #[test]
    fn apply_update_rejects_an_existing_member() {
        let k1 = make_key(1);
        let mut config = ThresholdConfig::try_new(vec![k1], nonzero(1)).unwrap();
        let update = ThresholdConfigUpdate::try_new(vec![k1], vec![], nonzero(1)).unwrap();

        assert_eq!(
            config.apply_update(&update),
            Err(ThresholdSignatureError::MemberAlreadyExists)
        );
    }

    #[test]
    fn apply_update_rejects_duplicates_within_a_list() {
        let mut config = ThresholdConfig::try_new(vec![make_key(1)], nonzero(1)).unwrap();
        let k2 = make_key(2);

        let dup_add = ThresholdConfigUpdate::try_new(vec![k2, k2], vec![], nonzero(1)).unwrap();
        assert_eq!(
            config.apply_update(&dup_add),
            Err(ThresholdSignatureError::DuplicateAddMember)
        );

        let k1 = make_key(1);
        let dup_remove = ThresholdConfigUpdate::try_new(vec![], vec![k1, k1], nonzero(1)).unwrap();
        assert_eq!(
            config.apply_update(&dup_remove),
            Err(ThresholdSignatureError::DuplicateRemoveMember)
        );
    }

    #[test]
    fn config_ssz_byte_layout() {
        let keys = vec![make_key(1), make_key(2), make_key(3)];
        let config = ThresholdConfig::try_new(keys.clone(), nonzero(2)).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&5u32.to_le_bytes()); // offset to keys
        expected.push(2); // threshold
        for key in &keys {
            expected.extend_from_slice(&key.serialize());
        }

        assert_eq!(config.as_ssz_bytes(), expected);
        assert_eq!(config.ssz_bytes_len(), expected.len());
        assert_eq!(ThresholdConfig::from_ssz_bytes(&expected).unwrap(), config);
    }

    #[test]
    fn update_ssz_byte_layout() {
        let add = vec![make_key(1), make_key(2)];
        let remove = vec![make_key(3)];
        let update =
            ThresholdConfigUpdate::try_new(add.clone(), remove.clone(), nonzero(2)).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&9u32.to_le_bytes()); // offset to add_members
        expected.extend_from_slice(&(9u32 + 2 * 33).to_le_bytes()); // offset to remove_members
        expected.push(2); // new_threshold
        for key in add.iter().chain(&remove) {
            expected.extend_from_slice(&key.serialize());
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
        bytes.extend_from_slice(&make_key(1).serialize());

        assert!(ThresholdConfig::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn config_ssz_rejects_a_non_curve_point() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0u8; 33]);

        assert!(ThresholdConfig::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn config_ssz_rejects_a_truncated_key() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&make_key(1).serialize()[..32]);

        assert!(ThresholdConfig::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn config_ssz_rejects_a_misplaced_offset() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&6u32.to_le_bytes()); // should be 5
        bytes.push(1);
        bytes.extend_from_slice(&make_key(1).serialize());

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

    /// Produces a valid config with distinct keys and an in-range threshold.
    fn arb_threshold_config() -> impl Strategy<Value = ThresholdConfig> {
        (1usize..=8)
            .prop_flat_map(|n| (Just(n), 1u8..=(n as u8)))
            .prop_map(|(n, threshold)| {
                let keys = (0..n as u32).map(make_key_n).collect::<Vec<_>>();
                ThresholdConfig::try_new(keys, nonzero(threshold))
                    .expect("keys and threshold are valid")
            })
    }

    /// Produces an update with disjoint add and remove lists.
    fn arb_threshold_update() -> impl Strategy<Value = ThresholdConfigUpdate> {
        (0usize..=4, 0usize..=4).prop_map(|(add, remove)| {
            let add_members = (0..add as u32).map(make_key_n).collect::<Vec<_>>();
            let remove_members = (100..100 + remove as u32)
                .map(make_key_n)
                .collect::<Vec<_>>();
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

        #[test]
        fn config_serde_json_roundtrips(config in arb_threshold_config()) {
            let json = serde_json::to_string(&config).unwrap();
            prop_assert_eq!(serde_json::from_str::<ThresholdConfig>(&json).unwrap(), config);
        }
    }
}
