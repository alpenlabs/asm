use strata_asm_common::AsmLog;
use strata_codec::{Codec, CodecError, Decoder, Encoder};
use strata_codec_utils::CodecSsz;
use strata_msg_fmt::TypeId;
use strata_predicate::PredicateKey;

use crate::constants::AsmLogTypeId;

/// Records an OL STF verifying-key rotation taking effect.
///
/// Emitted when the rotation actually becomes the active predicate, not when
/// it is authorized: a rotation is queued at the height that authorizes it and
/// activates once the verified checkpoint tip reaches that height. This log
/// rides in the manifest of the block where it activates, so the activation
/// height is implicit.
#[derive(Debug, Clone)]
pub struct CheckpointPredicateEnacted {
    /// OL STF verification predicate that is now active.
    new_predicate: PredicateKey,
}

impl CheckpointPredicateEnacted {
    /// Creates a log for a predicate rotation that has taken effect.
    pub fn new(new_predicate: PredicateKey) -> Self {
        Self { new_predicate }
    }

    /// Returns the new OL STF verification predicate.
    pub fn new_predicate(&self) -> &PredicateKey {
        &self.new_predicate
    }
}

impl Codec for CheckpointPredicateEnacted {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let new_predicate = CodecSsz::<PredicateKey>::decode(dec)?.into_inner();
        Ok(Self { new_predicate })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        CodecSsz::new(self.new_predicate.clone()).encode(enc)
    }
}

impl AsmLog for CheckpointPredicateEnacted {
    const TY: TypeId = AsmLogTypeId::CheckpointPredicateEnacted as TypeId;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_asm_common::AsmLogEntry;
    use strata_codec::{decode_buf_exact, encode_to_vec};
    use strata_predicate::{PredicateKey, PredicateTypeId, MAX_CONDITION_LEN};

    use super::*;

    // `strata_predicate::test_utils::predicate_key_strategy` is `pub(crate)`, so we
    // build a local equivalent. Varying condition length up to `MAX_CONDITION_LEN`
    // exercises the SSZ-encoding boundary that matters for the `from_log` budget.
    fn predicate_key_strategy() -> impl Strategy<Value = PredicateKey> {
        prop::collection::vec(any::<u8>(), 0..=MAX_CONDITION_LEN as usize).prop_map(|c| {
            PredicateKey::try_new(PredicateTypeId::AlwaysAccept, c)
                .expect("generated predicate is within the condition limit")
        })
    }

    proptest! {
        #[test]
        fn from_log_is_infallible(key in predicate_key_strategy()) {
            let log = CheckpointPredicateEnacted::new(key);
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn from_log_boundary_cases() {
        let cases = [
            CheckpointPredicateEnacted::new(
                PredicateKey::try_new(PredicateTypeId::AlwaysAccept, vec![])
                    .expect("empty predicate is within the condition limit"),
            ),
            CheckpointPredicateEnacted::new(
                PredicateKey::try_new(
                    PredicateTypeId::AlwaysAccept,
                    vec![0u8; MAX_CONDITION_LEN as usize],
                )
                .expect("boundary predicate is within the condition limit"),
            ),
        ];
        for log in cases {
            assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn checkpoint_predicate_enacted_roundtrip() {
        let new_predicate = PredicateKey::always_accept();
        let log = CheckpointPredicateEnacted::new(new_predicate.clone());

        let encoded = encode_to_vec(&log).expect("encoding should not fail");
        let decoded: CheckpointPredicateEnacted =
            decode_buf_exact(&encoded).expect("decoding should not fail");

        assert_eq!(decoded.new_predicate(), &new_predicate);
    }
}
