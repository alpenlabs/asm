//! Codec versioning and structural validation for proof-visible ASM state.
//!
//! Two independent version axes live in [`AnchorState`](crate::AnchorState):
//!
//! - the **anchor codec version**, which versions the container layout itself;
//! - a **section codec version** per [`SectionState`](crate::SectionState), declared by the
//!   subprotocol version that wrote it.
//!
//! Both are codec versions, not counters: they name a layout, so the executor
//! reading a section can tell whether it understands those bytes.
//!
//! Numbering starts at 0 and no value is reserved. A codec version and an
//! [`AsmSpecId`](strata_asm_common::AsmSpecId) are independent axes even where
//! their numbers happen to coincide: a subprotocol whose layout survives an
//! upgrade keeps its version across that boundary while its neighbours bump,
//! so the two never stay in step.

use strata_l1_txfmt::SubprotocolId;
use thiserror::Error;

/// Codec version of the current [`AnchorState`](crate::AnchorState) container.
///
/// This versions the *container* — `magic`, `chain_view`, the section list —
/// and is independent of any subprotocol's section version. Reshaping the
/// container introduces the next value here and a migration between them.
pub const ANCHOR_STATE_VERSION: u8 = 0;

/// One `(subprotocol id, section codec version)` pair required by a spec.
///
/// A spec's full schema is the ordered list of these pairs. Because the pair
/// includes the codec version, two specs that route the same subprotocol IDs
/// but read different section layouts have distinct schemas — which is what
/// lets a spec recognize state it has already migrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionSchema {
    id: SubprotocolId,
    version: u8,
}

impl SectionSchema {
    /// Declares that `id`'s section must carry codec version `version`.
    pub const fn new(id: SubprotocolId, version: u8) -> Self {
        Self { id, version }
    }

    /// Returns the stable subprotocol identifier.
    pub const fn id(self) -> SubprotocolId {
        self.id
    }

    /// Returns the required section codec version.
    pub const fn version(self) -> u8 {
        self.version
    }
}

/// Failure to validate proof-visible ASM state, structurally or against a
/// spec's declared schema.
#[derive(Debug, Error, PartialEq)]
pub enum StateValidationError {
    /// The payload was too short to expose its leading anchor codec version.
    #[error("anchor state payload is empty; cannot read its codec version")]
    MissingAnchorVersion,

    /// The anchor codec version is reserved or unknown to this build.
    #[error("unsupported anchor state codec version {actual}")]
    UnsupportedAnchorVersion {
        /// Version found in the payload.
        actual: u8,
    },

    /// Two sections shared one subprotocol identifier.
    #[error("duplicate state section for subprotocol {id}")]
    DuplicateSection {
        /// The repeated identifier.
        id: SubprotocolId,
    },

    /// Sections were not in canonical ascending subprotocol-ID order.
    #[error("state sections out of order: subprotocol {current} follows {previous}")]
    SectionsOutOfOrder {
        /// Identifier of the preceding section.
        previous: SubprotocolId,
        /// Identifier that broke the ordering.
        current: SubprotocolId,
    },

    /// The spec's schema requires a section the state does not carry.
    #[error("missing state section for subprotocol {id}")]
    MissingSection {
        /// Identifier required by the schema.
        id: SubprotocolId,
    },

    /// The state carries a section the spec's schema does not declare.
    ///
    /// This is rejected rather than ignored: the transition rebuilds the
    /// section list from the sections it routes, so an undeclared section
    /// would be silently dropped from the successor state.
    #[error("unexpected state section for subprotocol {id}")]
    UnexpectedSection {
        /// Identifier the schema does not declare.
        id: SubprotocolId,
    },

    /// A section's codec version is not the one the spec's schema declares.
    #[error("section for subprotocol {id} has codec version {actual}, schema requires {expected}")]
    SectionVersionMismatch {
        /// Stable subprotocol identifier.
        id: SubprotocolId,
        /// Version the schema declares.
        expected: u8,
        /// Version found in the state.
        actual: u8,
    },

    /// The schema itself names one subprotocol more than once.
    #[error("spec schema declares subprotocol {id} more than once")]
    DuplicateSchemaEntry {
        /// The repeated identifier.
        id: SubprotocolId,
    },

    /// The payload could not be decoded as the anchor state container.
    #[error("failed to decode anchor state: {0}")]
    Decode(#[from] ssz::DecodeError),

    /// Decoding and re-encoding the payload did not reproduce its bytes.
    ///
    /// Proofs bind to the state root, so a payload with more than one valid
    /// encoding is rejected at the boundary.
    #[error("anchor state encoding is not canonical")]
    NonCanonicalEncoding,
}
