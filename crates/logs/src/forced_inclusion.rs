use strata_asm_common::AsmLog;
use strata_codec::{Codec, VarVec};
use strata_msg_fmt::TypeId;

use crate::constants::FORCED_INCLUSION_LOG_TYPE_ID;

/// Details for a forced inclusion operation.
#[derive(Debug, Clone, Codec)]
pub struct ForcedInclusionData {
    /// Identifier of the target execution environment.
    pub ee_id: u64,
    /// Raw payload data for inclusion.
    pub payload: VarVec<u8>,
}

impl ForcedInclusionData {
    /// Create a new ForcedInclusionData instance.
    pub fn new(ee_id: u64, payload: Vec<u8>) -> Self {
        Self {
            ee_id,
            payload: VarVec::from_vec(payload).expect("payload too large for VarVec"),
        }
    }
}

impl AsmLog for ForcedInclusionData {
    const TY: TypeId = FORCED_INCLUSION_LOG_TYPE_ID;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_asm_common::AsmLogEntry;

    use super::*;

    // No upstream parser bounds `payload` (the type has no production callers yet).
    // Cap at a value that leaves room for the 8-byte `ee_id`, the VarVec length
    // varint, and the 1-byte SPS-52 header within MAX_LOG_DATA_BYTES = 4096.
    const MAX_PAYLOAD_LEN: usize = 4032;

    fn forced_inclusion_data_strategy() -> impl Strategy<Value = ForcedInclusionData> {
        (
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=MAX_PAYLOAD_LEN),
        )
            .prop_map(|(ee_id, payload)| ForcedInclusionData::new(ee_id, payload))
    }

    proptest! {
        #[test]
        fn from_log_is_infallible(log in forced_inclusion_data_strategy()) {
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn from_log_boundary_cases() {
        let cases = [
            (0u64, vec![]),
            (u64::MAX, vec![]),
            (0u64, vec![0xAB; MAX_PAYLOAD_LEN]),
            (u64::MAX, vec![0xAB; MAX_PAYLOAD_LEN]),
        ];
        for (ee_id, payload) in cases {
            let log = ForcedInclusionData::new(ee_id, payload);
            assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }
}
