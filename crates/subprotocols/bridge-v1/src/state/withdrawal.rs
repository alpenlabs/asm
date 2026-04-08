use strata_bridge_types::OperatorIdx;
use strata_codec::{Codec, encode_to_vec};
use strata_crypto::hash;

/// Represents an operator's claim to unlock a deposit UTXO after successful withdrawal fulfillment.
///
/// This structure is created when a withdrawal fulfillment transaction is successfully validated.
/// It serves as proof that a valid frontpayment was made matching the assignment specifications,
/// and authorizes the assigned operator to claim the corresponding locked deposit funds through
/// the Bridge proof system.
///
/// The claim contains:
/// - The deposit index that identifies which locked UTXO can be claimed
/// - The operator index of the assigned operator who is authorized to claim
///
/// # Important Notes
///
/// - The `operator_idx` always refers to the **assigned operator** from the assignment entry, not
///   necessarily the party who made the actual frontpayment (since frontpayment identity is not
///   validated during transaction processing).
/// - This data is stored in the MohoState and emitted as an ASM log via `NewExportEntry`.
/// - The Bridge proof system consumes these entries to verify operators have correctly fulfilled
///   withdrawal obligations before allowing them to unlock deposit UTXOs.
#[derive(Debug, Clone, PartialEq, Eq, Codec)]
pub struct OperatorClaimUnlock {
    /// The index of the deposit that was fulfilled.
    pub deposit_idx: u32,

    /// The index of the operator who was assigned to (and is authorized to claim) this withdrawal.
    pub operator_idx: OperatorIdx,
}

impl OperatorClaimUnlock {
    pub fn new(deposit_idx: u32, operator_idx: OperatorIdx) -> Self {
        Self {
            deposit_idx,
            operator_idx,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let buf = encode_to_vec(self).expect("failed to encode OperatorClaimUnlock");
        hash::raw(&buf).0
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn compute_hash_is_infallible(deposit_idx: u32, operator_idx: u32) {
            let claim = OperatorClaimUnlock::new(deposit_idx, operator_idx);
            // Should never panic for any input.
            let _hash = claim.compute_hash();
        }
    }
}

