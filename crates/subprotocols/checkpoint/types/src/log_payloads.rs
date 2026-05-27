//! Log payload types for orchestration layer logs.

use strata_codec::{Codec, VarVec};
use strata_msg_fmt::TypeId;

/// OL log type-id namespace.
///
/// These identify OL log payload types inside the `strata_msg_fmt` envelope carried in
/// [`OLLog::payload`](crate::OLLog). They are a **wire contract** and MUST stay in sync with
/// strata `crates/ol/chain-types/src/log_payloads.rs`: if the values diverge, withdrawal intents
/// silently vanish from checkpoints.
///
/// Note: this is a *different* namespace from the SPS-52 ASM log ids in `strata-asm-logs`; do not
/// reuse those.
///
/// `0x02` (snark account update) also exists in this namespace but is not consumed by checkpoint
/// verification.
pub const SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID: TypeId = 0x01;

/// Trait for OL log payload types carried in the `strata_msg_fmt` envelope.
///
/// Mirrors `AsmLog` (`strata-asm-manifest-types`): each OL log type has a unique [`TypeId`] used
/// to dispatch on the log's interpretation independently of the emitting account.
pub trait OLLogType: Codec {
    /// Unique type identifier for this OL log type.
    const TY: TypeId;
}

impl OLLogType for SimpleWithdrawalIntentLogData {
    const TY: TypeId = SIMPLE_WITHDRAWAL_INTENT_LOG_TYPE_ID;
}

/// Error decoding a typed OL log from an [`OLLog`](crate::OLLog)'s msg-fmt envelope.
#[derive(Debug, thiserror::Error)]
pub enum OLLogDecodeError {
    /// The envelope's type id did not match the requested log type.
    #[error("ol log type mismatch: expected {expected}, found {found}")]
    TypeMismatch {
        /// Type id requested by the caller.
        expected: TypeId,
        /// Type id found in the envelope.
        found: TypeId,
    },

    /// Failed to encode/decode the log body via the codec.
    #[error("codec: {0}")]
    Codec(#[from] strata_codec::CodecError),

    /// Failed to parse the msg-fmt envelope.
    #[error("msgfmt: {0:?}")]
    Envelope(#[from] strata_msg_fmt::Error),
}

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
