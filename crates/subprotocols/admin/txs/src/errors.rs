use strata_identifiers::Buf32;
use strata_l1_envelope_fmt::EnvelopeParseError;
use strata_l1_txfmt::TxType;
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

    /// A sequencer update's key is not a BIP340 x-only public key, so the sequencer could
    /// never sign a checkpoint envelope with it.
    #[error("sequencer update key {key} is not a BIP340 x-only public key")]
    InvalidSequencerKey { key: Buf32 },

    /// Failed to parse the transaction envelope.
    #[error("failed to parse transaction envelope: {0}")]
    MalformedEnvelope(#[from] EnvelopeParseError),
}
