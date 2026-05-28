use strata_asm_common::AsmLog;
use strata_codec::{Codec, VarVec};
use strata_msg_fmt::TypeId;

use crate::constants::AsmLogTypeId;

/// Details for a deposit operation.
#[derive(Debug, Clone, Codec)]
pub struct DepositLog {
    /// Destination
    pub destination: VarVec<u8>,
    /// Amount in satoshis.
    pub amount: u64,
}

impl DepositLog {
    /// Create a new DepositLog instance.
    pub fn new(destination: VarVec<u8>, amount: u64) -> Self {
        Self {
            destination,
            amount,
        }
    }
}

impl AsmLog for DepositLog {
    const TY: TypeId = AsmLogTypeId::Deposit as TypeId;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_asm_common::AsmLogEntry;

    use super::*;

    // Upstream the deposit-request parser caps `destination` at this size — see
    // `MAX_DESTINATION_LEN` in crates/subprotocols/bridge-v1/txs/src/deposit_request/aux.rs
    // (SPS-50 OP_RETURN budget). Hardcoded rather than imported to avoid a circular
    // dep on bridge-v1 from this crate.
    const MAX_DESTINATION_LEN: usize = 42;

    fn deposit_log_strategy() -> impl Strategy<Value = DepositLog> {
        (
            prop::collection::vec(any::<u8>(), 0..=MAX_DESTINATION_LEN),
            any::<u64>(),
        )
            .prop_map(|(dest, amount)| {
                DepositLog::new(VarVec::from_vec(dest).expect("within VarVec bound"), amount)
            })
    }

    proptest! {
        #[test]
        fn from_log_is_infallible(log in deposit_log_strategy()) {
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn from_log_boundary_cases() {
        let cases = [
            (vec![], 0u64),
            (vec![], u64::MAX),
            (vec![0xAB; MAX_DESTINATION_LEN], 0u64),
            (vec![0xAB; MAX_DESTINATION_LEN], u64::MAX),
        ];
        for (dest, amount) in cases {
            let log = DepositLog::new(VarVec::from_vec(dest).unwrap(), amount);
            assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }
}
