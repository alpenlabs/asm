use strata_asm_common::AsmLog;
use strata_codec::{Codec, CodecError, Decoder, Encoder};
use strata_codec_utils::CodecSsz;
use strata_msg_fmt::TypeId;
use strata_predicate::PredicateKey;

use crate::constants::AsmLogTypeId;

/// Details for an execution environment verification key update.
#[derive(Debug, Clone)]
pub struct AsmStfUpdate {
    /// New execution environment state transition function verification key.
    new_predicate: PredicateKey,
}

impl AsmStfUpdate {
    /// Create a new AsmStfUpdate instance.
    pub fn new(new_predicate: PredicateKey) -> Self {
        Self { new_predicate }
    }

    pub fn new_predicate(&self) -> &PredicateKey {
        &self.new_predicate
    }

    pub fn into_new_predicate(self) -> PredicateKey {
        self.new_predicate
    }
}

impl Codec for AsmStfUpdate {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let new_predicate = CodecSsz::<PredicateKey>::decode(dec)?.into_inner();
        Ok(Self { new_predicate })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        CodecSsz::new(self.new_predicate.clone()).encode(enc)
    }
}

impl AsmLog for AsmStfUpdate {
    const TY: TypeId = AsmLogTypeId::AsmStfUpdate as TypeId;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_asm_common::AsmLogEntry;
    use strata_predicate::{PredicateKey, PredicateTypeId, MAX_CONDITION_LEN};

    use super::*;

    // `strata_predicate::test_utils::predicate_key_strategy` is `pub(crate)`, so we
    // build a local equivalent. Varying condition length up to `MAX_CONDITION_LEN`
    // exercises the SSZ-encoding boundary that matters for the `from_log` budget.
    fn predicate_key_strategy() -> impl Strategy<Value = PredicateKey> {
        prop::collection::vec(any::<u8>(), 0..=MAX_CONDITION_LEN as usize)
            .prop_map(|c| PredicateKey::new(PredicateTypeId::AlwaysAccept, c))
    }

    proptest! {
        #[test]
        fn from_log_is_infallible(key in predicate_key_strategy()) {
            let log = AsmStfUpdate::new(key);
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn from_log_boundary_cases() {
        let cases = [
            AsmStfUpdate::new(PredicateKey::new(PredicateTypeId::AlwaysAccept, vec![])),
            AsmStfUpdate::new(PredicateKey::new(
                PredicateTypeId::AlwaysAccept,
                vec![0u8; MAX_CONDITION_LEN as usize],
            )),
        ];
        for log in cases {
            assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }
}
