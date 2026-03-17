use bitcoin::{Network, Work, block::Header, params::Params};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeDeError};
use ssz::{Decode, Encode};
use ssz_types::FixedBytes;
use strata_btc_types::GenesisL1View;
use strata_btc_verification::{
    HeaderVerificationState as NativeHeaderVerificationState, L1VerificationError,
};

use crate::{
    AnchorState, AsmError, AsmHistoryAccumulatorState, BtcParams, BtcWork, ChainViewState,
    HeaderVerificationState, Mismatched, SectionState, Subprotocol, SubprotocolId, TimestampStore,
};

#[derive(Serialize, Deserialize)]
struct TimestampStoreSerde {
    buffer: [u32; strata_btc_types::TIMESTAMPS_FOR_MEDIAN],
    head: usize,
}

#[derive(Serialize, Deserialize)]
struct HeaderVerificationStateSerde {
    params: strata_btc_types::BtcParams,
    last_verified_block: strata_identifiers::L1BlockCommitment,
    next_block_target: u32,
    epoch_start_timestamp: u32,
    block_timestamp_history: strata_btc_verification::TimestampStore,
    total_accumulated_pow: strata_btc_verification::BtcWork,
}

impl AnchorState {
    /// Gets a section by protocol ID by doing a linear scan.
    pub fn find_section(&self, id: SubprotocolId) -> Option<&SectionState> {
        self.sections.iter().find(|s| s.id == id)
    }
}

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
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Signet => 2,
            bitcoin::Network::Regtest => 3,
            other => panic!("asm: unsupported Bitcoin network {other:?}"),
        };

        Self { network }
    }

    /// Converts ASM SSZ params back into the native Bitcoin params wrapper.
    pub fn into_native(self) -> strata_btc_types::BtcParams {
        let network = match self.network {
            0 => bitcoin::Network::Bitcoin,
            1 => bitcoin::Network::Testnet,
            2 => bitcoin::Network::Signet,
            3 => bitcoin::Network::Regtest,
            other => panic!("asm: invalid stored Bitcoin network {other}"),
        };
        strata_btc_types::BtcParams::from(Params::from(network))
    }
}

impl BtcWork {
    /// Creates ASM SSZ work from the native work wrapper.
    pub fn from_native(work: strata_btc_verification::BtcWork) -> Self {
        let work_hex: String = serde_json::from_str(
            &serde_json::to_string(&work)
                .expect("asm: native accumulated work JSON serialization should not fail"),
        )
        .expect("asm: native accumulated work JSON should deserialize into a string");
        let bytes = Work::from_hex(&work_hex)
            .expect("asm: native accumulated work JSON should stay hex-encoded")
            .to_le_bytes();

        Self {
            bytes_le: FixedBytes::from(bytes),
        }
    }

    /// Converts ASM SSZ work back into the native work wrapper.
    pub fn into_native(self) -> strata_btc_verification::BtcWork {
        let bytes: [u8; 32] = self
            .bytes_le
            .as_ref()
            .try_into()
            .expect("asm: accumulated work must be 32 bytes");
        strata_btc_verification::BtcWork::from(Work::from_le_bytes(bytes))
    }
}

impl TimestampStore {
    /// Creates ASM SSZ timestamp state from the native timestamp store.
    pub fn from_native(store: strata_btc_verification::TimestampStore) -> Self {
        let decoded: TimestampStoreSerde = serde_json::from_value(
            serde_json::to_value(store)
                .expect("asm: native timestamp store JSON serialization should not fail"),
        )
        .expect("asm: native timestamp store JSON should match the expected shape");

        Self {
            buffer: decoded.buffer.to_vec().into(),
            head: decoded
                .head
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
        serde_json::from_value(serde_json::json!(TimestampStoreSerde {
            buffer,
            head: usize::from(self.head),
        }))
        .expect("asm: stored timestamp state must remain valid JSON")
    }
}

impl HeaderVerificationState {
    /// Creates ASM-local header verification state from the native Bitcoin verifier state.
    pub fn from_native(state: NativeHeaderVerificationState) -> Self {
        let decoded: HeaderVerificationStateSerde = serde_json::from_value(
            serde_json::to_value(state)
                .expect("asm: native header verification state JSON serialization should not fail"),
        )
        .expect("asm: native header verification state JSON should match the expected shape");

        Self {
            params: BtcParams::from_native(decoded.params),
            last_verified_block: decoded.last_verified_block,
            next_block_target: decoded.next_block_target,
            epoch_start_timestamp: decoded.epoch_start_timestamp,
            block_timestamp_history: TimestampStore::from_native(decoded.block_timestamp_history),
            total_accumulated_pow: BtcWork::from_native(decoded.total_accumulated_pow),
        }
    }

    /// Converts ASM-local header verification state back into the native verifier state.
    pub fn into_native(self) -> NativeHeaderVerificationState {
        serde_json::from_value(serde_json::json!(HeaderVerificationStateSerde {
            params: self.params.into_native(),
            last_verified_block: self.last_verified_block,
            next_block_target: self.next_block_target,
            epoch_start_timestamp: self.epoch_start_timestamp,
            block_timestamp_history: self.block_timestamp_history.into_native(),
            total_accumulated_pow: self.total_accumulated_pow.into_native(),
        }))
        .expect("asm: stored header verification state must remain valid JSON")
    }

    /// Constructs a new state from the L1 genesis view.
    pub fn new(network: Network, genesis_view: &GenesisL1View) -> Self {
        Self::from_native(NativeHeaderVerificationState::new(network, genesis_view))
    }

    /// Validates a header and updates the verifier state.
    pub fn check_and_update(&mut self, header: &Header) -> Result<(), L1VerificationError> {
        let mut native = self.clone().into_native();
        native.check_and_update(header)?;
        *self = Self::from_native(native);
        Ok(())
    }
}
