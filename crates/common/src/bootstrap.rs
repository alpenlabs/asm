//! The validated state a chain starts from.
//!
//! Genesis is a different lifecycle from the state transition: it happens once,
//! from operator-supplied params, and nothing in the per-block path reads those
//! params again. So it is not part of [`AsmSpec`](crate::AsmSpec) — a spec
//! answers only *what are the rules?*
//!
//! An [`AsmBootstrap`] is the handoff between the two: whoever holds the params
//! builds the genesis state and validates it here, and the worker receives a
//! value that is already known-good and already knows its own anchor height. The
//! worker therefore needs no params type at all.

use strata_identifiers::L1BlockCommitment;
use thiserror::Error;

use crate::{
    AnchorState, AsmHistoryAccumulatorState, AsmSpec, AsmSpecId, StateValidationError,
    validate_state_for_spec,
};

/// A validated ASM genesis state, tagged with the spec it was built for.
///
/// Validation here is structural and self-contained: it never contacts an L1
/// node. Checking that the embedded anchor matches the real L1 chain is the
/// worker's job, done against its own configured data source before it writes
/// anything.
#[derive(Clone, Debug)]
pub struct AsmBootstrap {
    spec_id: AsmSpecId,
    genesis_state: AnchorState,
}

impl AsmBootstrap {
    /// Validates `state` as the genesis state for specification `S`.
    ///
    /// Checks that the state is executable under `S` — exact section
    /// membership, `S`'s declared codec versions, decodable canonical payloads
    /// — and that its manifest history is correctly sentinel-prefilled for its
    /// anchor height.
    ///
    /// `S` is normally the chain's first specification, but a development chain
    /// may launch directly at a later one; the codec versions in the state are
    /// whatever `S` declares, so nothing here assumes a particular version.
    pub fn try_new<S: AsmSpec>(state: AnchorState) -> Result<Self, BootstrapError> {
        validate_state_for_spec::<S>(&state).map_err(|source| BootstrapError::NotExecutable {
            spec: S::ID,
            source: Box::new(source),
        })?;

        // The manifest MMR is height-indexed, so a state anchored at height `h`
        // must already hold `h + 1` sentinel leaves covering `0..=h`. Getting
        // this wrong misaligns every later manifest by a constant offset, which
        // would otherwise only surface as a proof mismatch much later.
        let anchor_height = u64::from(state.last_processed_block().height());
        let expected_entries = anchor_height + 1;
        let actual_entries = state.chain_view.history_accumulator.num_entries();
        if actual_entries != expected_entries {
            return Err(BootstrapError::HistoryBoundary {
                anchor_height,
                expected_entries,
                actual_entries,
            });
        }

        if state.chain_view.history_accumulator != AsmHistoryAccumulatorState::new(anchor_height) {
            return Err(BootstrapError::HistoryNotPrefilled { anchor_height });
        }

        Ok(Self {
            spec_id: S::ID,
            genesis_state: state,
        })
    }

    /// Returns the specification this genesis state was validated against.
    pub const fn spec_id(&self) -> AsmSpecId {
        self.spec_id
    }

    /// Borrows the validated genesis state.
    pub const fn genesis_state(&self) -> &AnchorState {
        &self.genesis_state
    }

    /// Consumes the bootstrap and returns its genesis state.
    pub fn into_genesis_state(self) -> AnchorState {
        self.genesis_state
    }

    /// Returns the L1 block this chain is anchored at.
    pub fn anchor_block(&self) -> L1BlockCommitment {
        self.genesis_state.last_processed_block()
    }

    /// Returns the L1 height this chain is anchored at.
    ///
    /// The manifest MMR is prefilled with sentinels through this height, so the
    /// first real manifest lands at `anchor_l1_height() + 1`.
    pub fn anchor_l1_height(&self) -> u64 {
        u64::from(self.anchor_block().height())
    }
}

/// Failure to accept a state as chain genesis.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The state is not executable under the specification it was built for.
    #[error("genesis state is not executable under ASM spec {spec}: {source}")]
    NotExecutable {
        /// Specification the state was validated against.
        spec: AsmSpecId,
        /// The validation failure.
        #[source]
        source: Box<crate::AsmError>,
    },

    /// The manifest history does not have one leaf per height through the anchor.
    #[error(
        "genesis manifest history at L1 height {anchor_height} has {actual_entries} entries, expected {expected_entries}"
    )]
    HistoryBoundary {
        /// Height committed by the genesis header-verification state.
        anchor_height: u64,
        /// Required sentinel leaf count.
        expected_entries: u64,
        /// Leaf count found in the state.
        actual_entries: u64,
    },

    /// The history has the right length but is not the sentinel prefill.
    #[error("genesis manifest history is not sentinel-prefilled through L1 height {anchor_height}")]
    HistoryNotPrefilled {
        /// Height committed by the genesis header-verification state.
        anchor_height: u64,
    },

    /// The state envelope itself was malformed.
    #[error(transparent)]
    State(#[from] StateValidationError),
}
