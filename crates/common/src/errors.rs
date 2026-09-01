use ssz::DecodeError;
// Re-export error types from manifest-types crate
pub use strata_asm_manifest_types::{AsmManifestError, AsmManifestResult, Mismatched};
use strata_btc_verification::{L1BodyError, L1VerificationError};
use strata_l1_txfmt::SubprotocolId;
use strata_merkle::MerkleError;
use thiserror::Error;

use crate::{AsmSpecId, StateValidationError, aux_input::AuxError};

/// Convenience result wrapper.
pub type AsmResult<T> = Result<T, AsmError>;

/// Errors that can occur while working with ASM subprotocols.
#[derive(Debug, Error)]
pub enum AsmError {
    /// Subprotocol ID of a decoded section did not match the expected subprotocol ID.
    #[error(transparent)]
    SubprotoIdMismatch(#[from] Mismatched<SubprotocolId>),

    /// The requested subprotocol ID was not found.
    #[error("subproto {0:?} does not exist")]
    InvalidSubprotocol(SubprotocolId),

    /// The requested subprotocol state ID was not found.
    #[error("subproto {0:?} state does not exist")]
    InvalidSubprotocolState(SubprotocolId),

    /// Failed to deserialize the state of the given subprotocol.
    #[error("failed to deserialize subprotocol {0} state: {1}")]
    Deserialization(SubprotocolId, #[source] DecodeError),

    /// Block body integrity check failed.
    #[error("block integrity check failed: {0}")]
    InvalidL1Body(#[from] L1BodyError),

    /// L1Header do not follow consensus rules.
    #[error("L1Header do not follow consensus rules: {0}")]
    InvalidL1Header(#[source] L1VerificationError),

    /// Missing genesis configuration for subprotocol
    #[error("missing genesis configuration for subprotocol {0}")]
    MissingGenesisConfig(SubprotocolId),

    /// Error related to Merkle tree operations
    #[error("merkle tree error: {0}")]
    MerkleError(#[from] MerkleError),

    /// Wrapped error from manifest-types crate
    #[error(transparent)]
    ManifestError(#[from] AsmManifestError),

    /// Failed to verify auxiliary data.
    #[error("invalid auxiliary data: {0}")]
    InvalidAuxData(#[from] AuxError),

    /// Serialised subprotocol state exceeds the section-data capacity
    /// (`MAX_SECTION_STATE_BYTES`).
    #[error("subprotocol {id} section too large: {source}")]
    SectionTooLarge {
        id: SubprotocolId,
        #[source]
        source: ssz_types::Error,
    },

    /// Too many sections to fit into the anchor state (`MAX_SECTIONS`).
    #[error("too many sections: {0}")]
    TooManySections(#[source] ssz_types::Error),

    /// The anchor state envelope or a spec's section schema was violated.
    #[error(transparent)]
    StateValidation(#[from] StateValidationError),

    /// A section's codec version is not the one this subprotocol version reads.
    ///
    /// On the boundary block this is expected and drives the migration; seen
    /// anywhere else it means state was routed to the wrong specification.
    #[error("subprotocol {id} section has codec version {actual}, this version reads {expected}")]
    SectionVersionMismatch {
        /// Stable subprotocol identifier.
        id: SubprotocolId,
        /// Version this implementation reads.
        expected: u8,
        /// Version found in the section.
        actual: u8,
    },

    /// A section payload was not the canonical encoding of its own value.
    #[error("subprotocol {id} section encoding is not canonical")]
    NonCanonicalSectionEncoding {
        /// Stable subprotocol identifier.
        id: SubprotocolId,
    },

    /// State did not match a specification's schema and that specification
    /// defines no migration into itself.
    ///
    /// Expected for the first specification, which has no predecessor. For any
    /// later one it means the state belongs to neither this spec nor its
    /// declared predecessor.
    #[error("no migration into ASM spec {into} is defined")]
    NoMigrationDefined {
        /// Specification the state was being prepared for.
        into: AsmSpecId,
    },
    /// State selected for migration did not match the target specification's
    /// exact direct predecessor schema.
    ///
    /// A generic schema mismatch is not sufficient evidence that a conversion
    /// is valid: the state could belong to an older or newer specification, or
    /// contain a partially migrated mix of section versions.
    #[error(
        "state cannot migrate into ASM spec {into} because it is not the direct predecessor: {source}"
    )]
    MigrationInputRejected {
        /// Specification the migration targeted.
        into: AsmSpecId,
        /// Difference from the declared predecessor schema.
        #[source]
        source: StateValidationError,
    },
    /// A migration ran but did not produce the target specification's schema.
    ///
    /// The framework checks this so a faulty conversion fails at the boundary
    /// instead of emitting state the pipeline cannot load.
    #[error("migration into ASM spec {into} did not produce its schema: {source}")]
    MigrationOutputRejected {
        /// Specification the migration targeted.
        into: AsmSpecId,
        /// The schema violation found in the output.
        #[source]
        source: StateValidationError,
    },

    /// Startup validation was wired to a specification other than the target's
    /// declared predecessor.
    ///
    /// This is a build-time target-table defect, not bad chain state. Keeping it
    /// fallible makes a bad release halt with the exact conflicting ids instead
    /// of trusting whichever validator happened to be called.
    #[error(
        "ASM spec {into} declares predecessor {declared}, but its state validator uses {validator}"
    )]
    PredecessorSpecMismatch {
        /// Successor whose declaration and validator disagree.
        into: AsmSpecId,
        /// Predecessor id declared by the successor.
        declared: AsmSpecId,
        /// Predecessor implementation supplied by the target table.
        validator: AsmSpecId,
    },

    /// The declared predecessor schema differs from the schema derived from
    /// that predecessor's implementation.
    #[error(
        "ASM spec {into} declares a predecessor schema that differs from ASM spec {predecessor}"
    )]
    PredecessorSchemaMismatch {
        /// Successor carrying the inconsistent declaration.
        into: AsmSpecId,
        /// Predecessor implementation used for canonical payload validation.
        predecessor: AsmSpecId,
    },

    /// A subprotocol's state conversion failed at an upgrade boundary.
    ///
    /// The conversions live in the subprotocol crates that own the new layouts,
    /// so their error types are not visible here; the reason is carried as text.
    #[error("migrating subprotocol {id} state failed: {reason}")]
    MigrationFailed {
        /// Stable subprotocol identifier.
        id: SubprotocolId,
        /// Rendering of the subprotocol's own conversion error.
        reason: String,
    },
}
