use strata_asm_params::AdminTxType;
/// Defines the sighash payload contributions for a multisig action.
///
/// Each multisig action type implements this trait to provide the data used in
/// computing its signature hash. [`tx_type`](Sighash::tx_type) identifies the
/// action and [`sighash_payload`](Sighash::sighash_payload) returns the
/// action-specific bytes included in the hash.
pub trait Sighash {
    /// Returns the [`AdminTxType`] that identifies this action.
    fn tx_type(&self) -> AdminTxType;

    /// Returns the action-specific payload bytes used in sighash computation.
    fn sighash_payload(&self) -> Vec<u8>;
}
