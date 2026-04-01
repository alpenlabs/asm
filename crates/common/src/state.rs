use bitcoin::{Network, block::Header, params::Params};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeDeError};
use ssz::{Decode, Encode};
use ssz_types::FixedBytes;
use strata_btc_verification::{
    HeaderVerificationState as NativeHeaderVerificationState, L1Anchor, L1VerificationError,
};
use strata_l1_txfmt::MagicBytes;

use crate::{
    AnchorState, AsmError, AsmHistoryAccumulatorState, BtcParams, BtcWork, ChainViewState,
    HeaderVerificationState, Mismatched, SectionState, Subprotocol, SubprotocolId, TimestampStore,
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
    pub fn new(id: SubprotocolId, data: Vec<u8>) -> Self {
        Self {
            id,
            data: data.into(),
        }
    }

    /// Constructs an instance by serializing a subprotocol state.
    pub fn from_state<S: Subprotocol>(state: &S::State) -> Self {
        Self::new(S::ID, state.as_ssz_bytes())
    }

    /// Tries to deserialize the section data as a particular subprotocol's state.
    pub fn try_to_state<S: Subprotocol>(&self) -> Result<S::State, AsmError> {
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

impl BtcParams {
    /// Creates ASM SSZ params from the native Bitcoin params wrapper.
    pub fn from_native(params: strata_btc_types::BtcParams) -> Self {
        let network = match params.inner().network {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
            Network::Signet => 2,
            Network::Regtest => 3,
            unsupported => panic!("asm: unsupported Bitcoin network {unsupported:?}"),
        };

        Self { network }
    }

    /// Converts ASM SSZ params back into the native Bitcoin params wrapper.
    pub fn into_native(self) -> strata_btc_types::BtcParams {
        let network = match self.network {
            0 => Network::Bitcoin,
            1 => Network::Testnet,
            2 => Network::Signet,
            3 => Network::Regtest,
            unsupported => panic!("asm: unsupported Bitcoin network id {unsupported}"),
        };
        strata_btc_types::BtcParams::from(Params::from(network))
    }
}

impl BtcWork {
    /// Creates ASM SSZ work from the native work wrapper.
    pub fn from_native(work: strata_btc_verification::BtcWork) -> Self {
        Self {
            bytes_le: FixedBytes::from(work.to_le_bytes()),
        }
    }

    /// Converts ASM SSZ work back into the native work wrapper.
    pub fn into_native(self) -> strata_btc_verification::BtcWork {
        let bytes: [u8; 32] = self
            .bytes_le
            .as_ref()
            .try_into()
            .expect("asm: accumulated work must be 32 bytes");
        strata_btc_verification::BtcWork::from_le_bytes(bytes)
    }
}

impl TimestampStore {
    /// Creates ASM SSZ timestamp state from the native timestamp store.
    pub fn from_native(store: strata_btc_verification::TimestampStore) -> Self {
        let (buffer, head): ([u32; strata_btc_types::TIMESTAMPS_FOR_MEDIAN], usize) =
            store.into_parts();

        Self {
            buffer: buffer.to_vec().into(),
            head: head
                .try_into()
                .expect("asm: timestamp store head always fits into u8"),
        }
    }

    /// Converts ASM SSZ timestamp state back into the native timestamp store.
    pub fn into_native(self) -> strata_btc_verification::TimestampStore {
        let buffer: [u32; strata_btc_types::TIMESTAMPS_FOR_MEDIAN] = self
            .buffer
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .expect("asm: timestamp store buffer must contain the expected number of entries");
        strata_btc_verification::TimestampStore::from_parts(buffer, usize::from(self.head))
    }
}

impl HeaderVerificationState {
    /// Creates ASM-local header verification state from the native Bitcoin verifier state.
    pub fn from_native(state: NativeHeaderVerificationState) -> Self {
        let (
            params,
            last_verified_block,
            next_block_target,
            epoch_start_timestamp,
            block_timestamp_history,
            total_accumulated_pow,
        ): (
            strata_btc_types::BtcParams,
            strata_identifiers::L1BlockCommitment,
            u32,
            u32,
            strata_btc_verification::TimestampStore,
            strata_btc_verification::BtcWork,
        ) = state.into_parts();

        Self {
            params: BtcParams::from_native(params),
            last_verified_block,
            next_block_target,
            epoch_start_timestamp,
            block_timestamp_history: TimestampStore::from_native(block_timestamp_history),
            total_accumulated_pow: BtcWork::from_native(total_accumulated_pow),
        }
    }

    /// Converts ASM-local header verification state back into the native verifier state.
    pub fn into_native(self) -> NativeHeaderVerificationState {
        NativeHeaderVerificationState::from_parts(
            self.params.into_native(),
            self.last_verified_block,
            self.next_block_target,
            self.epoch_start_timestamp,
            self.block_timestamp_history.into_native(),
            self.total_accumulated_pow.into_native(),
        )
    }

    /// Creates a fresh state from an [`L1Anchor`].
    pub fn init(anchor: L1Anchor) -> Self {
        Self::from_native(NativeHeaderVerificationState::init(anchor))
    }

    /// Validates a header and updates the verifier state.
    pub fn check_and_update(&mut self, header: &Header) -> Result<(), L1VerificationError> {
        let mut native = self.clone().into_native();
        native.check_and_update(header)?;
        *self = Self::from_native(native);
        Ok(())
    }
}
