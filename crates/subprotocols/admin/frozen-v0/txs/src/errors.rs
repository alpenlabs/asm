use strata_l1_envelope_fmt::errors::EnvelopeParseError;
use strata_l1_txfmt::TxType;
use thiserror::Error;

/// Top-level error type for the administration subprotocol, composed of smaller error categories.
#[derive(Debug, Error)]
pub enum AdministrationTxParseError {
    /// The transaction witness does not carry a taproot leaf script holding the payload.
    #[error("admin tx for tx_type = {0} is missing its taproot leaf script payload")]
    MissingPayloadScript(TxType),

    /// The SSZ-encoded signed payload (action + signatures) could not be deserialized.
    #[error("failed to deserialize admin payload for tx_type = {tx_type}: {reason}")]
    MalformedPayload { tx_type: TxType, reason: String },

    /// Failed to parse the transaction envelope.
    #[error("failed to parse transaction envelope: {0}")]
    MalformedEnvelope(#[from] EnvelopeParseError),

    /// Failed to deserialize the transaction payload for the given transaction type.
    #[error("tx type is not defined")]
    UnknownTxType,
}
