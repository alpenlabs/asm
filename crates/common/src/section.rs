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

#[cfg(test)]
mod tests {
    use ssz_types::VariableList;
    use strata_identifiers::L1BlockCommitment;

    use super::*;
    use crate::{
        HeaderVerificationState, MsgRelayer, NullMsg, SubprotocolId, TxInputRef, VerifiedAuxData,
    };

    const TEST_ID: SubprotocolId = 200;

    /// Large enough that an encoded state can exceed `MAX_SECTION_STATE_BYTES`.
    type OversizedState = VariableList<u8, { 2 * 1024 * 1024 }>;

    struct TestSubproto;

    impl Subprotocol for TestSubproto {
        const ID: SubprotocolId = TEST_ID;
        const STATE_VERSION: u8 = 0;
        type InitConfig = ();
        type State = u64;
        type Msg = NullMsg<TEST_ID>;

        fn init(_config: &Self::InitConfig) -> Self::State {
            0
        }

        fn process_txs(
            _state: &mut Self::State,
            _txs: &[TxInputRef<'_>],
            _header_vs: &HeaderVerificationState,
            _verified_aux_data: &VerifiedAuxData,
            _relayer: &mut impl MsgRelayer,
        ) {
        }

        fn process_msgs(_state: &mut Self::State, _msgs: &[Self::Msg], _l1ref: &L1BlockCommitment) {
        }
    }

    struct OversizedSubproto;

    impl Subprotocol for OversizedSubproto {
        const ID: SubprotocolId = TEST_ID;
        const STATE_VERSION: u8 = 0;
        type InitConfig = ();
        type State = OversizedState;
        type Msg = NullMsg<TEST_ID>;

        fn init(_config: &Self::InitConfig) -> Self::State {
            OversizedState::default()
        }

        fn process_txs(
            _state: &mut Self::State,
            _txs: &[TxInputRef<'_>],
            _header_vs: &HeaderVerificationState,
            _verified_aux_data: &VerifiedAuxData,
            _relayer: &mut impl MsgRelayer,
        ) {
        }

        fn process_msgs(_state: &mut Self::State, _msgs: &[Self::Msg], _l1ref: &L1BlockCommitment) {
        }
    }

    #[test]
    fn state_roundtrip() {
        let section = SectionState::from_state::<TestSubproto>(&7u64).expect("fits capacity");
        assert_eq!(section.id, TEST_ID);
        assert_eq!(
            section.try_to_state::<TestSubproto>().expect("decode"),
            7u64
        );
    }

    #[test]
    fn try_to_state_rejects_wrong_id() {
        let section = SectionState::new(TEST_ID + 1, 7u64.as_ssz_bytes()).expect("fits capacity");
        assert!(matches!(
            section.try_to_state::<TestSubproto>(),
            Err(AsmError::SubprotoIdMismatch(_))
        ));
    }

    #[test]
    fn try_to_state_rejects_undecodable_data() {
        let section = SectionState::new(TEST_ID, vec![0u8; 3]).expect("fits capacity");
        assert!(matches!(
            section.try_to_state::<TestSubproto>(),
            Err(AsmError::Deserialization(TEST_ID, _))
        ));
    }

    #[test]
    fn from_state_rejects_oversized_state() {
        let state = OversizedState::new(vec![0u8; 1 + (1 << 20)]).expect("within list bound");
        assert!(matches!(
            SectionState::from_state::<OversizedSubproto>(&state),
            Err(AsmError::SectionTooLarge { id: TEST_ID, .. })
        ));
    }
}
