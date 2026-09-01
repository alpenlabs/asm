use strata_asm_common::{AsmLog, AsmLogEntry};
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
        prop::collection::vec(any::<u8>(), 0..=MAX_CONDITION_LEN as usize).prop_map(|c| {
            PredicateKey::try_new(PredicateTypeId::AlwaysAccept, c)
                .expect("generated predicate is within the condition limit")
        })
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
            AsmStfUpdate::new(
                PredicateKey::try_new(PredicateTypeId::AlwaysAccept, vec![])
                    .expect("empty predicate is within the condition limit"),
            ),
            AsmStfUpdate::new(
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
}

/// Returns the predicate an ordered log list hands over, if it enacts one.
///
/// **This is the single definition of the handover.** Two components need the
/// answer — the Moho program, whose result the proof chain authenticates, and
/// the ASM worker, which must execute the next block under exactly those rules.
/// They cannot each derive it: a block carrying two updates would make "first"
/// and "last" disagree, and the worker would then execute under rules no proof
/// authorizes. So both call this.
///
/// The *first* enacting log wins, because that is what the proof chain has
/// always taken, and the proof chain is the authority.
pub fn extract_next_predicate_from_logs(logs: &[AsmLogEntry]) -> Option<PredicateKey> {
    logs.iter().find_map(|log| {
        log.try_into_log::<AsmStfUpdate>()
            .ok()
            .map(|update| update.new_predicate().clone())
    })
}

#[cfg(test)]
mod handover_tests {
    use strata_asm_common::AsmLogEntry;
    use strata_predicate::{PredicateKey, PredicateTypeId};

    use super::*;

    fn predicate(seed: u8) -> PredicateKey {
        PredicateKey::try_new(PredicateTypeId::Bip340Schnorr, vec![seed; 32])
            .expect("valid predicate")
    }

    fn log(to: &PredicateKey) -> AsmLogEntry {
        AsmLogEntry::from_log(&AsmStfUpdate::new(to.clone()))
            .expect("AsmStfUpdate encoding is infallible")
    }

    #[test]
    fn no_enacting_log_hands_over_nothing() {
        assert_eq!(extract_next_predicate_from_logs(&[]), None);
    }

    #[test]
    fn a_single_enacting_log_hands_over_its_predicate() {
        assert_eq!(
            extract_next_predicate_from_logs(&[log(&predicate(2))]),
            Some(predicate(2)),
        );
    }

    /// Pins the tie-break the two consumers must agree on. Were this to change,
    /// the ASM worker and the proof chain would disagree about which rules the
    /// next block runs under — silently, on a block carrying two updates.
    #[test]
    fn the_first_enacting_log_wins() {
        let logs = [log(&predicate(2)), log(&predicate(3))];
        assert_eq!(
            extract_next_predicate_from_logs(&logs),
            Some(predicate(2)),
            "the proof chain takes the first; the worker must match",
        );
    }
}
