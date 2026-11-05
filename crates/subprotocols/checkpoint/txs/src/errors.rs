use strata_codec::CodecError;
use strata_l1_envelope_fmt::SignedEnvelopeSpendError;
use thiserror::Error;

/// Errors that can occur while parsing checkpoint transactions from SPS-50 envelopes.
#[derive(Debug, Error)]
pub enum CheckpointTxError {
    /// Encountered an SPS-50 tag with an unexpected transaction type.
    #[error("unsupported checkpoint tx type: expected {expected}, got {actual}")]
    UnexpectedTxType { expected: u8, actual: u8 },

    /// Transaction did not contain any inputs.
    #[error("checkpoint transaction missing inputs")]
    MissingInputs,

    /// The first input is not an SPS-51 signed envelope spend.
    #[error("checkpoint transaction carries no signed envelope in its first input: {0}")]
    EnvelopeSpend(#[from] SignedEnvelopeSpendError),

    /// Failed to decode the checkpoint payload via strata-codec.
    #[error("failed to decode checkpoint payload: {0}")]
    CodecDecode(CodecError),
}

/// Result alias for checkpoint transaction helpers.
pub type CheckpointTxResult<T> = Result<T, CheckpointTxError>;
