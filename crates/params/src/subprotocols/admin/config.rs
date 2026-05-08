use std::num::NonZero;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use strata_crypto::threshold_signature::ThresholdConfig;

use crate::{ConfirmationDepths, Role};

/// Initialization configuration for the administration subprotocol, containing [`ThresholdConfig`]
/// for each role.
///
/// Design choice: Uses individual named fields rather than `Vec<(Role, ThresholdConfig)>`
/// to ensure structural completeness - the compiler guarantees all config fields are
/// provided when constructing this struct. However, it does NOT prevent logical errors
/// like using the same config for multiple roles or mismatched role-field assignments.
/// The benefit is avoiding missing fields at compile-time rather than runtime validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct AdministrationInitConfig {
    /// ThresholdConfig for [StrataAdministrator](Role::StrataAdministrator).
    pub strata_administrator: ThresholdConfig,

    /// ThresholdConfig for [StrataSequencerManager](Role::StrataSequencerManager).
    pub strata_sequencer_manager: ThresholdConfig,

    /// ThresholdConfig for [AlpenAdministrator](Role::AlpenAdministrator).
    pub alpen_administrator: ThresholdConfig,

    /// Per-variant confirmation depths (CD) for queued admin updates.
    pub confirmation_depths: ConfirmationDepths,

    /// Maximum allowed gap between consecutive sequence numbers for a given authority.
    ///
    /// A payload with `seqno > last_seqno + max_seqno_gap` is rejected. This prevents
    /// excessively large jumps in sequence numbers while still allowing non-sequential usage.
    #[ssz(with = "non_zero_u8")]
    pub max_seqno_gap: NonZero<u8>,
}

impl AdministrationInitConfig {
    pub fn new(
        strata_administrator: ThresholdConfig,
        strata_sequencer_manager: ThresholdConfig,
        alpen_administrator: ThresholdConfig,
        confirmation_depths: ConfirmationDepths,
        max_seqno_gap: NonZero<u8>,
    ) -> Self {
        Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            confirmation_depths,
            max_seqno_gap,
        }
    }

    pub fn get_config(&self, role: Role) -> &ThresholdConfig {
        match role {
            Role::StrataAdministrator => &self.strata_administrator,
            Role::StrataSequencerManager => &self.strata_sequencer_manager,
            Role::AlpenAdministrator => &self.alpen_administrator,
        }
    }

    pub fn get_all_authorities(self) -> Vec<(Role, ThresholdConfig)> {
        vec![
            (Role::StrataAdministrator, self.strata_administrator),
            (Role::StrataSequencerManager, self.strata_sequencer_manager),
            (Role::AlpenAdministrator, self.alpen_administrator),
        ]
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AdministrationInitConfig {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let strata_administrator = u.arbitrary()?;
        let strata_sequencer_manager = u.arbitrary()?;
        let alpen_administrator = u.arbitrary()?;
        let confirmation_depths = u.arbitrary()?;
        // Generate a valid NonZero<u8> by mapping [0, 255) to [1, 256) via saturating add.
        let raw: u8 = u.arbitrary()?;
        let max_seqno_gap = NonZero::new(raw.saturating_add(1))
            .expect("saturating_add(1) on u8 always produces a non-zero value");

        Ok(Self {
            strata_administrator,
            strata_sequencer_manager,
            alpen_administrator,
            confirmation_depths,
            max_seqno_gap,
        })
    }
}

#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod non_zero_u8 {
    pub mod encode {
        use std::num::NonZero;

        use ssz::Encode as SszEncode;

        pub fn is_ssz_fixed_len() -> bool {
            <u8 as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <u8 as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &NonZero<u8>) -> usize {
            value.get().ssz_bytes_len()
        }

        pub fn ssz_append(value: &NonZero<u8>, buf: &mut Vec<u8>) {
            value.get().ssz_append(buf);
        }
    }

    pub mod decode {
        use std::num::NonZero;

        use ssz::{Decode as SszDecode, DecodeError};

        pub fn is_ssz_fixed_len() -> bool {
            <u8 as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <u8 as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<NonZero<u8>, DecodeError> {
            let value = u8::from_ssz_bytes(bytes)?;
            NonZero::new(value)
                .ok_or_else(|| DecodeError::BytesInvalid("max_seqno_gap must be non-zero".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use proptest::prelude::*;

    use super::non_zero_u8;

    proptest! {
        #[test]
        fn test_non_zero_u8_ssz_roundtrip(raw in 1u8..=u8::MAX) {
            let value = NonZero::new(raw).expect("raw is non-zero");
            let mut buf = Vec::new();
            non_zero_u8::encode::ssz_append(&value, &mut buf);
            let decoded = non_zero_u8::decode::from_ssz_bytes(&buf)
                .expect("roundtrip should succeed for non-zero u8");
            prop_assert_eq!(decoded, value);
        }
    }

    #[test]
    fn test_non_zero_u8_ssz_decode_zero_fails() {
        assert!(non_zero_u8::decode::from_ssz_bytes(&[0u8]).is_err());
    }
}
