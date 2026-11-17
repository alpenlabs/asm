use strata_l1_envelope_fmt::EnvelopeParseError;
use strata_l1_txfmt::TxType;
use strata_predicate::PredicateError;
use thiserror::Error;

/// Top-level error type for the administration subprotocol, composed of smaller error categories.
#[derive(Debug, Error)]
pub enum AdministrationTxParseError {
    /// The transaction has no inputs, or its witness does not carry a taproot leaf script
    /// holding the payload.
    #[error("admin tx for tx_type = {0} is missing its taproot leaf script payload")]
    MissingPayloadScript(TxType),

    /// The SSZ-encoded signed payload (action + signatures) could not be deserialized.
    #[error("failed to deserialize admin payload for tx_type = {tx_type}: {reason}")]
    MalformedPayload { tx_type: TxType, reason: String },

    /// The update decoded but its contents fail [`UpdateAction::validate`].
    ///
    /// [`UpdateAction::validate`]: crate::actions::UpdateAction::validate
    #[error("invalid admin update for tx_type = {tx_type}: {source}")]
    InvalidUpdate {
        tx_type: TxType,
        #[source]
        source: UpdateValidationError,
    },

    /// Failed to parse the transaction envelope.
    #[error("failed to parse transaction envelope: {0}")]
    MalformedEnvelope(#[from] EnvelopeParseError),
}

/// Why an update's contents are invalid.
#[derive(Debug, Error)]
pub enum UpdateValidationError {
    /// The predicate key's condition doesn't parse for its predicate type, so the key could
    /// never verify anything.
    #[error("malformed predicate condition: {0}")]
    MalformedPredicateCondition(#[source] PredicateError),
}
