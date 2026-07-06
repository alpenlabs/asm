use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeDeError};
use ssz::{Decode, Encode};
use ssz_types::{FixedBytes, VariableList};
use strata_btc_verification::HeaderVerificationState;
use strata_identifiers::L1BlockCommitment;
use strata_l1_txfmt::{MagicBytes, SubprotocolId};

use crate::{AnchorState, AsmHistoryAccumulatorState, ChainViewState, SectionState};

impl AnchorState {
    /// Gets a section by protocol ID by doing a linear scan.
    pub fn find_section(&self, id: SubprotocolId) -> Option<&SectionState> {
        self.sections.iter().find(|s| s.id == id)
    }

    pub fn magic(&self) -> MagicBytes {
        MagicBytes::from(self.magic.0)
    }

    /// Creates the SSZ magic field from `MagicBytes`.
    pub fn magic_ssz(magic: MagicBytes) -> FixedBytes<4> {
        FixedBytes::from(magic.into_inner())
    }

    /// Returns the last processed L1 block, i.e. this state was created by
    /// processing blocks up to and including this one.
    pub fn last_processed_block(&self) -> L1BlockCommitment {
        self.chain_view.pow_state.last_verified_block
    }
}

// Keep Borsh only as a thin compatibility shim; SSZ remains the canonical state encoding.
strata_identifiers::impl_borsh_via_ssz!(AnchorState);

impl Serialize for AnchorState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.as_ssz_bytes())
    }
}

impl<'de> Deserialize<'de> for AnchorState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
        Self::from_ssz_bytes(&bytes).map_err(SerdeDeError::custom)
    }
}

impl ChainViewState {
    /// Destructures the chain view into its constituent parts.
    pub fn into_parts(self) -> (HeaderVerificationState, AsmHistoryAccumulatorState) {
        (self.pow_state, self.history_accumulator)
    }
}

impl SectionState {
    /// Constructs a new instance.
    ///
    /// Errors if `data` exceeds the SSZ capacity for the section data field
    /// (`MAX_SECTION_STATE_BYTES`).
    pub fn new(id: SubprotocolId, data: Vec<u8>) -> Result<Self, ssz_types::Error> {
        let data = VariableList::new(data)?;
        Ok(Self { id, data })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::L1BlockCommitment;

    use super::*;

    /// Byte position of the pow state's network id within an encoded
    /// [`AnchorState`]: magic (4) + two offsets (8) put `chain_view` at 12,
    /// and the network id is the first byte of its fixed-size `pow_state`.
    const NETWORK_ID_POS: usize = 12;

    fn sample_anchor_state() -> AnchorState {
        let anchor = L1Anchor {
            block: L1BlockCommitment::default(),
            next_target: 0x1d00ffff,
            epoch_start_timestamp: 1_231_006_505,
            network: Network::Signet,
        };
        AnchorState {
            magic: AnchorState::magic_ssz(MagicBytes::from(*b"alpn")),
            chain_view: crate::ChainViewState {
                pow_state: HeaderVerificationState::init(anchor),
                history_accumulator: AsmHistoryAccumulatorState::new(0),
            },
            sections: vec![SectionState::new(1, vec![1, 2, 3]).expect("fits capacity")]
                .try_into()
                .expect("fits capacity"),
        }
    }

    #[test]
    fn anchor_state_ssz_roundtrip() {
        let state = sample_anchor_state();
        let bytes = state.as_ssz_bytes();
        let decoded = AnchorState::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(state, decoded);
    }

    #[test]
    fn anchor_state_serde_roundtrip() {
        let state = sample_anchor_state();
        let json = serde_json::to_string(&state).expect("serialize");
        let decoded: AnchorState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, decoded);
    }

    #[test]
    fn anchor_state_accessors() {
        let state = sample_anchor_state();
        assert_eq!(state.magic(), MagicBytes::from(*b"alpn"));
        assert!(state.find_section(1).is_some());
        assert!(state.find_section(99).is_none());

        let (pow_state, _history) = state.chain_view.clone().into_parts();
        assert_eq!(pow_state, state.chain_view.pow_state);
    }

    #[test]
    fn anchor_state_decode_rejects_unknown_network() {
        let mut bytes = sample_anchor_state().as_ssz_bytes();
        assert_eq!(bytes[NETWORK_ID_POS], 2, "expected Signet network id");
        bytes[NETWORK_ID_POS] = 42;
        // Must surface as a decode error, not a panic further down the line.
        assert!(AnchorState::from_ssz_bytes(&bytes).is_err());
    }
}
