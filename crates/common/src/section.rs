//! Subprotocol-aware helpers for [`SectionState`].
//!
//! [`SectionState`] is defined in `strata-asm-state`, which knows nothing
//! about the [`Subprotocol`] trait, so the typed conversions live here as an
//! extension trait.
//!
//! Every conversion is checked on two axes before any bytes are interpreted:
//! the stable subprotocol id, and the section codec version. The version check
//! matters because SSZ is not self-describing — two different layouts can both
//! decode from the same bytes, so without it a subprotocol version could
//! silently read its predecessor's state as its own.

use ssz::{Decode, Encode};

use crate::{AsmError, Mismatched, SectionState, Subprotocol};

/// Extension trait tying [`SectionState`] to the [`Subprotocol`] framework.
pub trait SectionStateExt: Sized {
    /// Serializes a subprotocol state, stamping the writer's codec version.
    ///
    /// The version comes from [`Subprotocol::STATE_VERSION`], so the bytes
    /// always carry the identity of the layout that produced them.
    fn from_state<S: Subprotocol>(state: &S::State) -> Result<Self, AsmError>;

    /// Decodes the section data as `S`'s state.
    ///
    /// Rejects a mismatched subprotocol id or codec version before decoding.
    /// This is the per-block `LOAD` path, so it does not verify that the
    /// payload is the *canonical* encoding of the decoded value; see
    /// [`verify_canonical`](Self::verify_canonical).
    fn try_to_state<S: Subprotocol>(&self) -> Result<S::State, AsmError>;

    /// Decodes as [`try_to_state`](Self::try_to_state) and additionally checks
    /// that the payload is the canonical encoding of the decoded value.
    ///
    /// The anchor envelope's own canonical check cannot cover this: section
    /// `data` is an opaque byte list there, so a non-canonical inner payload
    /// passes through the envelope unchanged. Proofs bind to the state root, so
    /// bytes with a second valid encoding are rejected — at boundaries where
    /// new bytes appear (genesis, migration output, storage load) rather than
    /// on every block.
    fn verify_canonical<S: Subprotocol>(&self) -> Result<S::State, AsmError>;
}

impl SectionStateExt for SectionState {
    fn from_state<S: Subprotocol>(state: &S::State) -> Result<Self, AsmError> {
        Self::new(S::ID, S::STATE_VERSION, state.as_ssz_bytes())
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

        if S::STATE_VERSION != self.version {
            return Err(AsmError::SectionVersionMismatch {
                id: self.id,
                expected: S::STATE_VERSION,
                actual: self.version,
            });
        }

        <S::State as Decode>::from_ssz_bytes(&self.data)
            .map_err(|e| AsmError::Deserialization(self.id, e))
    }

    fn verify_canonical<S: Subprotocol>(&self) -> Result<S::State, AsmError> {
        let state = self.try_to_state::<S>()?;
        if state.as_ssz_bytes().as_slice() != self.data.as_ref() {
            return Err(AsmError::NonCanonicalSectionEncoding { id: self.id });
        }
        Ok(state)
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

    /// Declares a subprotocol whose only interesting properties are its id,
    /// codec version, and state type.
    macro_rules! test_subproto {
        ($name:ident, $id:expr, $version:expr, $state:ty, $init:expr) => {
            struct $name;

            impl Subprotocol for $name {
                const ID: SubprotocolId = $id;
                const STATE_VERSION: u8 = $version;
                type InitConfig = ();
                type State = $state;
                type Msg = NullMsg<$id>;

                fn init(_config: &Self::InitConfig) -> Self::State {
                    $init
                }

                fn process_txs(
                    _state: &mut Self::State,
                    _txs: &[TxInputRef<'_>],
                    _header_vs: &HeaderVerificationState,
                    _verified_aux_data: &VerifiedAuxData,
                    _relayer: &mut impl MsgRelayer,
                ) {
                }

                fn process_msgs(
                    _state: &mut Self::State,
                    _msgs: &[Self::Msg],
                    _l1ref: &L1BlockCommitment,
                ) {
                }
            }
        };
    }

    test_subproto!(TestSubproto, TEST_ID, 0, u64, 0);
    // Same id and state type, next codec version: stands in for the successor
    // version of one subprotocol.
    test_subproto!(NextVersion, TEST_ID, 1, u64, 0);
    test_subproto!(
        OversizedSubproto,
        TEST_ID,
        0,
        OversizedState,
        OversizedState::default()
    );

    #[test]
    fn state_roundtrip_stamps_the_writers_version() {
        let section = SectionState::from_state::<TestSubproto>(&7u64).expect("fits capacity");
        assert_eq!(section.id, TEST_ID);
        assert_eq!(section.version, TestSubproto::STATE_VERSION);
        assert_eq!(
            section.try_to_state::<TestSubproto>().expect("decode"),
            7u64
        );
    }

    #[test]
    fn try_to_state_rejects_wrong_id() {
        let section =
            SectionState::new(TEST_ID + 1, 1, 7u64.as_ssz_bytes()).expect("fits capacity");
        assert!(matches!(
            section.try_to_state::<TestSubproto>(),
            Err(AsmError::SubprotoIdMismatch(_))
        ));
    }

    /// The decisive case for a declared codec version: both versions share a
    /// state type, so the bytes decode perfectly well under either. Only the
    /// version stamp distinguishes them, and reading a predecessor's section as
    /// the successor's layout must fail loudly rather than succeed quietly.
    #[test]
    fn try_to_state_rejects_another_versions_section_that_would_decode() {
        let section = SectionState::from_state::<TestSubproto>(&7u64).expect("fits capacity");
        assert!(
            <u64 as Decode>::from_ssz_bytes(&section.data).is_ok(),
            "the payload does decode under the successor's state type",
        );
        assert!(matches!(
            section.try_to_state::<NextVersion>(),
            Err(AsmError::SectionVersionMismatch {
                id: TEST_ID,
                expected: 1,
                actual: 0,
            })
        ));
    }

    #[test]
    fn try_to_state_rejects_undecodable_data() {
        let section = SectionState::new(TEST_ID, 0, vec![0u8; 3]).expect("fits capacity");
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

    /// A trailing byte the decoder tolerates makes the payload non-canonical:
    /// the envelope cannot see it, so the section-level check must.
    #[test]
    fn verify_canonical_rejects_a_non_canonical_payload() {
        let mut data = 7u64.as_ssz_bytes();
        data.push(0);
        let section = SectionState::new(TEST_ID, 0, data).expect("fits capacity");

        match section.verify_canonical::<TestSubproto>() {
            Err(AsmError::NonCanonicalSectionEncoding { id: TEST_ID })
            | Err(AsmError::Deserialization(TEST_ID, _)) => {}
            other => panic!("expected a rejection, got {other:?}"),
        }

        let canonical = SectionState::from_state::<TestSubproto>(&7u64).expect("fits capacity");
        assert_eq!(
            canonical
                .verify_canonical::<TestSubproto>()
                .expect("decode"),
            7u64
        );
    }
}
