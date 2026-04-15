use ssz::DecodeError;
use strata_l1_envelope_fmt::errors::EnvelopeParseError;
use thiserror::Error;

use crate::constants::AdminTxType;

/// Top-level error type for the administration subprotocol, composed of smaller error categories.
#[derive(Debug, Error)]
pub enum AdministrationTxParseError {
    /// The tagged admin tx type is not recognized by this build.
    #[error("unsupported admin tx type {raw_tx_type}")]
    UnknownTxType { raw_tx_type: u8 },

    /// The transaction did not contain the expected first input.
    #[error("missing input at index {index} for {tx_type}")]
    MissingInput { tx_type: AdminTxType, index: usize },

    /// The first input witness did not contain a taproot leaf script.
    #[error("missing taproot leaf script for {tx_type}")]
    MissingLeafScript { tx_type: AdminTxType },

    /// Failed to parse the transaction envelope.
    #[error("failed to parse envelope for {tx_type}: {source}")]
    MalformedEnvelope {
        tx_type: AdminTxType,
        #[source]
        source: EnvelopeParseError,
    },

    /// Failed to deserialize the transaction payload for the given transaction type.
    #[error("failed to deserialize payload for {tx_type}: {source}")]
    MalformedPayload {
        tx_type: AdminTxType,
        #[source]
        source: DecodeError,
    },

    /// The multisig threshold encoded in the payload is invalid.
    #[error("invalid threshold in payload for {tx_type}")]
    InvalidThreshold { tx_type: AdminTxType },
}
