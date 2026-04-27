//! Log payload types for orchestration layer logs.

use strata_codec::{Codec, VarVec};

/// Payload for a simple withdrawal intent log.
///
/// Emitted by the OL STF when a withdrawal message is processed at the bridge
/// gateway account.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
pub struct SimpleWithdrawalIntentLogData {
    /// Amount being withdrawn (sats).
    pub amt: u64,

    /// Destination BOSD.
    pub dest: VarVec<u8>,

    /// User's selected operator index for withdrawal assignment.
    // TODO(STR-1861): encode as varint to reduce DA cost in checkpoint payloads.
    pub selected_operator: u32,
}

impl SimpleWithdrawalIntentLogData {
    /// Create a new simple withdrawal intent log data instance.
    pub fn new(amt: u64, dest: Vec<u8>, selected_operator: u32) -> Option<Self> {
        let dest = VarVec::from_vec(dest)?;
        Some(Self {
            amt,
            dest,
            selected_operator,
        })
    }

    /// Get the withdrawal amount.
    pub fn amt(&self) -> u64 {
        self.amt
    }

    /// Get the destination as bytes.
    pub fn dest(&self) -> &[u8] {
        self.dest.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use strata_codec::{decode_buf_exact, encode_to_vec};

    use super::*;

    #[test]
    fn test_simple_withdrawal_intent_log_data_codec() {
        // Create test data
        let log_data = SimpleWithdrawalIntentLogData {
            amt: 100_000_000, // 1 BTC
            dest: VarVec::from_vec(b"bc1qtest123456789".to_vec()).unwrap(),
            selected_operator: 42,
        };

        // Encode
        let encoded = encode_to_vec(&log_data).unwrap();

        // Decode
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        // Verify round-trip
        assert_eq!(decoded.amt, log_data.amt);
        assert_eq!(decoded.dest.as_ref(), log_data.dest.as_ref());
        assert_eq!(decoded.selected_operator, log_data.selected_operator);
    }

    #[test]
    fn test_simple_withdrawal_intent_empty_dest() {
        // Test with empty destination (probably invalid, but codec should handle it)
        let log_data = SimpleWithdrawalIntentLogData {
            amt: 50_000,
            dest: VarVec::from_vec(vec![]).unwrap(),
            selected_operator: 0,
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.amt, 50_000);
        assert!(decoded.dest.is_empty());
    }

    #[test]
    fn test_simple_withdrawal_intent_max_values() {
        // Test with maximum values
        let log_data = SimpleWithdrawalIntentLogData {
            amt: u64::MAX,
            dest: VarVec::from_vec(vec![255u8; 200]).unwrap(),
            selected_operator: u32::MAX,
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.amt, u64::MAX);
        assert_eq!(decoded.dest.len(), 200);
        assert_eq!(decoded.dest.as_ref(), &vec![255u8; 200][..]);
    }

    #[test]
    fn test_simple_withdrawal_intent_zero_amount() {
        // Test with zero amount
        let log_data = SimpleWithdrawalIntentLogData {
            amt: 0,
            dest: VarVec::from_vec(b"addr1test".to_vec()).unwrap(),
            selected_operator: 5,
        };

        let encoded = encode_to_vec(&log_data).unwrap();
        let decoded: SimpleWithdrawalIntentLogData = decode_buf_exact(&encoded).unwrap();

        assert_eq!(decoded.amt, 0);
        assert_eq!(decoded.dest.as_ref(), b"addr1test");
    }
}
