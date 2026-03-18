use std::num::NonZero;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use strata_crypto::threshold_signature::ThresholdConfig;

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

    /// The confirmation depth (CD) setting, in Bitcoin blocks: after an update transaction
    /// receives this many confirmations, the update is enacted automatically. During this
    /// confirmation period, the update can still be cancelled by submitting a cancel transaction.
    pub confirmation_depth: u16,

    /// Maximum allowed gap between consecutive sequence numbers for a given authority.
    ///
    /// A payload with `seqno > last_seqno + max_seqno_gap` is rejected. This prevents
    /// excessively large jumps in sequence numbers while still allowing non-sequential usage.
    pub max_seqno_gap: NonZero<u8>,
}

#[derive(Debug, Encode, Decode)]
struct AdministrationInitConfigSsz {
    strata_administrator: ThresholdConfig,
    strata_sequencer_manager: ThresholdConfig,
    confirmation_depth: u16,
    max_seqno_gap: u8,
}

impl From<&AdministrationInitConfig> for AdministrationInitConfigSsz {
    fn from(value: &AdministrationInitConfig) -> Self {
        Self {
            strata_administrator: value.strata_administrator.clone(),
            strata_sequencer_manager: value.strata_sequencer_manager.clone(),
            confirmation_depth: value.confirmation_depth,
            max_seqno_gap: value.max_seqno_gap.get(),
        }
    }
}

impl TryFrom<AdministrationInitConfigSsz> for AdministrationInitConfig {
    type Error = DecodeError;

    fn try_from(value: AdministrationInitConfigSsz) -> Result<Self, Self::Error> {
        let max_seqno_gap = NonZero::new(value.max_seqno_gap)
            .ok_or_else(|| DecodeError::BytesInvalid("max_seqno_gap must be non-zero".into()))?;
        Ok(Self {
            strata_administrator: value.strata_administrator,
            strata_sequencer_manager: value.strata_sequencer_manager,
            confirmation_depth: value.confirmation_depth,
            max_seqno_gap,
        })
    }
}

impl SszEncode for AdministrationInitConfig {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        AdministrationInitConfigSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        AdministrationInitConfigSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for AdministrationInitConfig {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        AdministrationInitConfigSsz::from_ssz_bytes(bytes)?.try_into()
    }
}

/// Roles with authority in the administration subprotocol.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(u8)]
pub enum Role {
    /// The multisig authority that has exclusive ability to:
    /// 1. update (add/remove) bridge signers
    /// 2. update (add/remove) bridge operators
    /// 3. update the definition of what is considered a valid bridge deposit address for:
    ///    - registering deposit UTXOs
    ///    - accepting and minting bridge deposits
    ///    - assigning registered UTXOs to withdrawal requests
    /// 4. update the verifying key for the OL STF
    StrataAdministrator,

    /// The multisig authority that has exclusive ability to change the canonical
    /// public key of the default orchestration layer sequencer.
    StrataSequencerManager,
}

impl SszEncode for Role {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        (*self as u8).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }
}

impl SszDecode for Role {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        match u8::from_ssz_bytes(bytes)? {
            0 => Ok(Self::StrataAdministrator),
            1 => Ok(Self::StrataSequencerManager),
            value => Err(DecodeError::BytesInvalid(format!(
                "invalid role value {value}"
            ))),
        }
    }
}

impl AdministrationInitConfig {
    pub fn new(
        strata_administrator: ThresholdConfig,
        strata_sequencer_manager: ThresholdConfig,
        confirmation_depth: u16,
        max_seqno_gap: NonZero<u8>,
    ) -> Self {
        Self {
            strata_administrator,
            strata_sequencer_manager,
            confirmation_depth,
            max_seqno_gap,
        }
    }

    pub fn get_config(&self, role: Role) -> &ThresholdConfig {
        match role {
            Role::StrataAdministrator => &self.strata_administrator,
            Role::StrataSequencerManager => &self.strata_sequencer_manager,
        }
    }

    pub fn get_all_authorities(self) -> Vec<(Role, ThresholdConfig)> {
        vec![
            (Role::StrataAdministrator, self.strata_administrator),
            (Role::StrataSequencerManager, self.strata_sequencer_manager),
        ]
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AdministrationInitConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let strata_administrator = u.arbitrary()?;
        let strata_sequencer_manager = u.arbitrary()?;
        let confirmation_depth = u.arbitrary()?;
        // Generate a valid NonZero<u8> by mapping [0, 255) to [1, 256) via saturating add.
        let raw: u8 = u.arbitrary()?;
        let max_seqno_gap = NonZero::new(raw.saturating_add(1))
            .expect("saturating_add(1) on u8 always produces a non-zero value");

        Ok(Self {
            strata_administrator,
            strata_sequencer_manager,
            confirmation_depth,
            max_seqno_gap,
        })
    }
}
