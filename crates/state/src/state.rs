use std::cmp::Ordering;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeDeError,
    ser::Error as SerdeSerError,
};
use ssz::{Decode, Encode};
use ssz_types::{FixedBytes, VariableList};
use strata_btc_verification::HeaderVerificationState;
use strata_identifiers::L1BlockCommitment;
use strata_l1_txfmt::{MagicBytes, SubprotocolId};

use crate::{
    ANCHOR_STATE_VERSION, AnchorState, AsmHistoryAccumulatorState, ChainViewState, SectionSchema,
    SectionState, StateValidationError,
};

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

    /// Validates the spec-independent invariants of the state envelope.
    ///
    /// This checks what holds for every ASM specification: a supported anchor
    /// codec version, and a section list that is canonically ordered and free of
    /// duplicates. Section codec versions are deliberately *not* checked here —
    /// which version each section must carry is a per-spec fact, answered by
    /// [`validate_schema`](Self::validate_schema), which reports a mismatch with
    /// both the expected and actual version.
    pub fn validate(&self) -> Result<(), StateValidationError> {
        if self.version != ANCHOR_STATE_VERSION {
            return Err(StateValidationError::UnsupportedAnchorVersion {
                actual: self.version,
            });
        }

        let mut previous: Option<SubprotocolId> = None;
        for section in &self.sections {
            if let Some(previous) = previous {
                match section.id.cmp(&previous) {
                    Ordering::Equal => {
                        return Err(StateValidationError::DuplicateSection { id: section.id });
                    }
                    Ordering::Less => {
                        return Err(StateValidationError::SectionsOutOfOrder {
                            previous,
                            current: section.id,
                        });
                    }
                    Ordering::Greater => {}
                }
            }
            previous = Some(section.id);
        }

        Ok(())
    }

    /// Validates that this state carries exactly the sections a spec declares,
    /// each at the declared codec version.
    ///
    /// Membership is checked in both directions. A missing section means the
    /// spec cannot run; an undeclared one means the state belongs to a
    /// different spec, and letting it through would silently drop that section
    /// from the successor state, because the transition rebuilds the section
    /// list from the sections it routes.
    ///
    /// This does not decode section payloads. A spec that needs the payloads to
    /// be well-formed checks that separately, against its own state types.
    pub fn validate_schema(&self, schema: &[SectionSchema]) -> Result<(), StateValidationError> {
        self.validate()?;

        for (index, entry) in schema.iter().enumerate() {
            if schema[..index].iter().any(|prior| prior.id() == entry.id()) {
                return Err(StateValidationError::DuplicateSchemaEntry { id: entry.id() });
            }

            let section = self
                .find_section(entry.id())
                .ok_or(StateValidationError::MissingSection { id: entry.id() })?;

            if section.version != entry.version() {
                return Err(StateValidationError::SectionVersionMismatch {
                    id: entry.id(),
                    expected: entry.version(),
                    actual: section.version,
                });
            }
        }

        if let Some(section) = self
            .sections
            .iter()
            .find(|section| !schema.iter().any(|entry| entry.id() == section.id))
        {
            return Err(StateValidationError::UnexpectedSection { id: section.id });
        }

        Ok(())
    }

    /// Decodes one canonically encoded anchor state.
    ///
    /// The leading byte is the anchor codec version, so an unsupported version
    /// is reported as such instead of surfacing as a field-level decode error.
    /// Re-encoding must reproduce the input exactly: proofs bind to the state
    /// root, so a payload with a second valid encoding is rejected here.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, StateValidationError> {
        let version = *bytes
            .first()
            .ok_or(StateValidationError::MissingAnchorVersion)?;
        if version != ANCHOR_STATE_VERSION {
            return Err(StateValidationError::UnsupportedAnchorVersion { actual: version });
        }

        let state = Self::from_ssz_bytes(bytes)?;
        state.validate()?;
        if state.as_ssz_bytes() != bytes {
            return Err(StateValidationError::NonCanonicalEncoding);
        }

        Ok(state)
    }
}

impl Serialize for AnchorState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(SerdeSerError::custom)?;
        serializer.serialize_bytes(&self.as_ssz_bytes())
    }
}

impl<'de> Deserialize<'de> for AnchorState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
        Self::decode_canonical(&bytes).map_err(SerdeDeError::custom)
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
    /// `version` is the codec version of `data`, declared by the subprotocol
    /// version that produced it.
    ///
    /// Errors if `data` exceeds the SSZ capacity for the section data field
    /// (`MAX_SECTION_STATE_BYTES`).
    pub fn new(id: SubprotocolId, version: u8, data: Vec<u8>) -> Result<Self, ssz_types::Error> {
        let data = VariableList::new(data)?;
        Ok(Self { id, version, data })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use strata_btc_verification::L1Anchor;
    use strata_identifiers::L1BlockCommitment;

    use super::*;

    /// Byte position of the pow state's network id within an encoded
    /// [`AnchorState`]: version (1) + magic (4) + two offsets (8) put
    /// `chain_view` at 13, and the network id is the first byte of its
    /// fixed-size `pow_state`.
    const NETWORK_ID_POS: usize = 13;

    const V1: u8 = 1;

    fn section(id: SubprotocolId, version: u8) -> SectionState {
        SectionState::new(id, version, vec![1, 2, 3]).expect("fits capacity")
    }

    fn anchor_state(sections: Vec<SectionState>) -> AnchorState {
        let anchor = L1Anchor {
            block: L1BlockCommitment::default(),
            next_target: 0x1d00ffff,
            epoch_start_timestamp: 1_231_006_505,
            network: Network::Signet,
        };
        AnchorState {
            version: ANCHOR_STATE_VERSION,
            magic: AnchorState::magic_ssz(MagicBytes::from(*b"alpn")),
            chain_view: crate::ChainViewState {
                pow_state: HeaderVerificationState::init(anchor),
                history_accumulator: AsmHistoryAccumulatorState::new(0),
            },
            sections: sections.try_into().expect("fits capacity"),
        }
    }

    fn sample_anchor_state() -> AnchorState {
        anchor_state(vec![section(1, V1)])
    }

    #[test]
    fn anchor_state_ssz_roundtrip() {
        let state = sample_anchor_state();
        let bytes = state.as_ssz_bytes();
        let decoded = AnchorState::decode_canonical(&bytes).expect("decode");
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

    /// The codec version is the first wire byte, so it can be read without
    /// decoding the container.
    #[test]
    fn anchor_version_is_the_first_wire_byte() {
        let bytes = sample_anchor_state().as_ssz_bytes();
        assert_eq!(bytes[0], ANCHOR_STATE_VERSION);
    }

    /// A section's codec version immediately follows its id, so `[id, version]`
    /// is readable from the section prefix.
    #[test]
    fn section_version_follows_id_on_wire() {
        let bytes = section(7, 3).as_ssz_bytes();
        assert_eq!(bytes[..2], [7, 3]);
    }

    #[test]
    fn decode_rejects_empty_and_unsupported_anchor_versions() {
        assert_eq!(
            AnchorState::decode_canonical(&[]),
            Err(StateValidationError::MissingAnchorVersion),
        );

        let mut bytes = sample_anchor_state().as_ssz_bytes();
        bytes[0] = ANCHOR_STATE_VERSION + 1;
        assert_eq!(
            AnchorState::decode_canonical(&bytes),
            Err(StateValidationError::UnsupportedAnchorVersion {
                actual: ANCHOR_STATE_VERSION + 1,
            }),
        );
    }

    /// Adding `version` to the container shifted the SSZ layout, so state
    /// written before section versioning does not decode at all, and in
    /// particular is not readable as a section at any codec version.
    ///
    /// The pre-versioning `SectionState { id, data }` had a 5-byte fixed part
    /// (`id` plus a 4-byte offset for `data`), so its offset was 5. Read with
    /// the current decoder, byte 1 is that offset's low byte, and the four
    /// bytes after it are a garbage offset. This pins the reasoning: nothing
    /// needs to reserve a sentinel version to detect old state, because old
    /// state cannot be mistaken for new state in the first place.
    #[test]
    fn pre_versioning_section_bytes_do_not_decode() {
        // `{ id: 7, data: [1, 2, 3] }` in the pre-versioning layout.
        let released = [7u8, 5, 0, 0, 0, 1, 2, 3];

        assert_eq!(
            released[1], 5,
            "byte 1 is the old data offset, so it would read as version 5, not 0",
        );
        assert!(
            SectionState::from_ssz_bytes(&released).is_err(),
            "pre-versioning section bytes must not decode under the current layout",
        );

        // For contrast, the same logical section in the current layout has a
        // 6-byte fixed part and therefore offset 6.
        let current = section(7, 1).as_ssz_bytes();
        assert_eq!(current[..6], [7, 1, 6, 0, 0, 0]);
    }

    #[test]
    fn validate_rejects_duplicate_and_misordered_sections() {
        let duplicated = anchor_state(vec![section(4, V1), section(4, V1)]);
        assert_eq!(
            duplicated.validate(),
            Err(StateValidationError::DuplicateSection { id: 4 }),
        );

        let misordered = anchor_state(vec![section(9, V1), section(4, V1)]);
        assert_eq!(
            misordered.validate(),
            Err(StateValidationError::SectionsOutOfOrder {
                previous: 9,
                current: 4,
            }),
        );
    }

    #[test]
    fn validate_schema_accepts_the_exact_declared_set() {
        let state = anchor_state(vec![section(1, V1), section(2, 2)]);
        let schema = [SectionSchema::new(1, V1), SectionSchema::new(2, 2)];
        assert_eq!(state.validate_schema(&schema), Ok(()));
    }

    /// Membership is checked both ways: a schema entry with no section, and a
    /// section no schema entry declares, are both errors.
    #[test]
    fn validate_schema_checks_membership_in_both_directions() {
        let state = anchor_state(vec![section(1, V1)]);
        assert_eq!(
            state.validate_schema(&[SectionSchema::new(1, V1), SectionSchema::new(2, V1)]),
            Err(StateValidationError::MissingSection { id: 2 }),
        );
        assert_eq!(
            state.validate_schema(&[]),
            Err(StateValidationError::UnexpectedSection { id: 1 }),
        );
    }

    /// The codec version is what distinguishes one spec's schema from
    /// another's over the same subprotocol set.
    #[test]
    fn validate_schema_rejects_a_section_at_another_specs_version() {
        let state = anchor_state(vec![section(1, V1)]);
        assert_eq!(
            state.validate_schema(&[SectionSchema::new(1, 2)]),
            Err(StateValidationError::SectionVersionMismatch {
                id: 1,
                expected: 2,
                actual: V1,
            }),
        );
    }

    #[test]
    fn validate_schema_rejects_a_schema_naming_one_subprotocol_twice() {
        let state = anchor_state(vec![section(1, V1)]);
        assert_eq!(
            state.validate_schema(&[SectionSchema::new(1, V1), SectionSchema::new(1, V1)]),
            Err(StateValidationError::DuplicateSchemaEntry { id: 1 }),
        );
    }
}
