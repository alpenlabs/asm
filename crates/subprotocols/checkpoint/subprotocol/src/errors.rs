use bitcoin::OutPoint;
use strata_asm_common::AuxError;
use strata_asm_proto_checkpoint_txs::CheckpointTxError;
use strata_checkpoint_verification::CheckpointValidationError;
use strata_l1_envelope_fmt::SignedEnvelopeSpendError;
use thiserror::Error;

/// Reasons a transaction does not yield a checkpoint payload authenticated as the sequencer's.
///
/// Returned by [`verify_envelope_key`](crate::verify_envelope_key),
/// [`authenticate_checkpoint_envelope`](crate::authenticate_checkpoint_envelope) and
/// [`authenticate_checkpoint_tx`](crate::authenticate_checkpoint_tx).
#[derive(Debug, Error)]
pub enum CheckpointEnvelopeError {
    /// The transaction carries no checkpoint envelope, or its payload does not decode.
    #[error(transparent)]
    Envelope(#[from] CheckpointTxError),

    /// The envelope pubkey is not the sequencer key.
    #[error(transparent)]
    SequencerKey(#[from] CheckpointValidationError),

    /// The verified aux data lacks the output the envelope input spends.
    ///
    /// Unlike every other variant this says nothing about the transaction: it means the aux
    /// data requested for it was not provided.
    #[error("spent output {outpoint} missing from verified aux data: {source}")]
    MissingSpentOutput {
        /// The outpoint the envelope input spends.
        outpoint: OutPoint,
        /// Why the aux lookup failed.
        #[source]
        source: AuxError,
    },

    /// The output the envelope input spends is not a native P2TR output, so Bitcoin never ran
    /// the envelope leaf.
    #[error(transparent)]
    SpentOutput(#[from] SignedEnvelopeSpendError),
}
