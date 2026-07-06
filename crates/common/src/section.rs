//! Subprotocol-aware helpers for [`SectionState`].
//!
//! [`SectionState`] is defined in `strata-asm-state`, which knows nothing
//! about the [`Subprotocol`] trait, so the typed conversions live here as an
//! extension trait.

use ssz::{Decode, Encode};

use crate::{AsmError, Mismatched, SectionState, Subprotocol};

/// Extension trait tying [`SectionState`] to the [`Subprotocol`] framework.
pub trait SectionStateExt: Sized {
    /// Constructs an instance by serializing a subprotocol state.
    fn from_state<S: Subprotocol>(state: &S::State) -> Result<Self, AsmError>;

    /// Tries to deserialize the section data as a particular subprotocol's state.
    fn try_to_state<S: Subprotocol>(&self) -> Result<S::State, AsmError>;
}

impl SectionStateExt for SectionState {
    fn from_state<S: Subprotocol>(state: &S::State) -> Result<Self, AsmError> {
        Self::new(S::ID, state.as_ssz_bytes())
            .map_err(|source| AsmError::SectionTooLarge { id: S::ID, source })
    }

    fn try_to_state<S: Subprotocol>(&self) -> Result<S::State, AsmError> {
        if S::ID != self.id {
            return Err(Mismatched {
                expected: S::ID,
                actual: self.id,
            }
            .into());
        }

        <S::State as Decode>::from_ssz_bytes(&self.data)
            .map_err(|e| AsmError::Deserialization(self.id, e))
    }
}
