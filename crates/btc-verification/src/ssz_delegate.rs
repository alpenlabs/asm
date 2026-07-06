//! SSZ encoding for [`HeaderVerificationState`] via the delegate pattern.
//!
//! The wire layout is defined entirely by the generated
//! [`HeaderVerificationStateSsz`] container (see `ssz/header_verification.ssz`); this
//! module
//! only supplies the value-level conversions, so the encoding is correct by
//! construction and decoding validates invariants (known network id,
//! in-bounds ring-buffer head) instead of panicking downstream.

use std::marker::PhantomData;

use bitcoin::{Network, params::Params};
use ssz::{
    Decode, DecodeError,
    view::{DecodeView, SszTypeInfo},
};
use ssz_primitives::U256;
use ssz_types::view::ToOwnedSsz;
use strata_btc_types::BtcParams;
use strata_identifiers::{SszDelegate, impl_ssz_via_delegate};

use crate::{
    BtcWork, HeaderVerificationState, TIMESTAMPS_FOR_MEDIAN, TimestampStore,
    ssz_generated::ssz::header_verification::{
        HeaderVerificationStateSsz, TIMESTAMPS_FOR_MEDIAN as SSZ_TIMESTAMPS_FOR_MEDIAN,
        TimestampStoreSsz,
    },
};

// The schema redeclares the ring-buffer length; keep the two in sync.
const _: () = assert!(
    SSZ_TIMESTAMPS_FOR_MEDIAN as usize == TIMESTAMPS_FOR_MEDIAN,
    "ssz/header_verification.ssz TIMESTAMPS_FOR_MEDIAN must match the native constant"
);

/// Maps a Bitcoin network to its serialized identifier.
fn network_to_id(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
        unsupported => panic!("asm: unsupported Bitcoin network {unsupported:?}"),
    }
}

/// Maps a serialized network identifier back to the Bitcoin network.
fn network_from_id(id: u8) -> Result<Network, DecodeError> {
    match id {
        0 => Ok(Network::Bitcoin),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Signet),
        3 => Ok(Network::Regtest),
        unsupported => Err(DecodeError::BytesInvalid(format!(
            "unsupported Bitcoin network id {unsupported}"
        ))),
    }
}

impl SszDelegate for HeaderVerificationState {
    type Delegate = HeaderVerificationStateSsz;

    fn into_delegate(self) -> Self::Delegate {
        let (
            params,
            last_verified_block,
            next_block_target,
            epoch_start_timestamp,
            block_timestamp_history,
            total_accumulated_pow,
        ) = self.into_parts();
        let (buffer, head) = block_timestamp_history.into_parts();

        HeaderVerificationStateSsz {
            network: network_to_id(params.inner().network),
            last_verified_block,
            next_block_target,
            epoch_start_timestamp,
            block_timestamp_history: TimestampStoreSsz {
                buffer: buffer.into(),
                head: head
                    .try_into()
                    .expect("asm: timestamp store head always fits into u8"),
            },
            total_accumulated_pow: U256::from_le_bytes(total_accumulated_pow.to_le_bytes()),
        }
    }

    fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
        let network = network_from_id(delegate.network)?;

        let head = usize::from(delegate.block_timestamp_history.head);
        if head >= TIMESTAMPS_FOR_MEDIAN {
            return Err(DecodeError::BytesInvalid(format!(
                "timestamp store head {head} out of bounds (must be < {TIMESTAMPS_FOR_MEDIAN})"
            )));
        }
        let buffer: [u32; TIMESTAMPS_FOR_MEDIAN] =
            Vec::from(delegate.block_timestamp_history.buffer)
                .try_into()
                .expect("asm: fixed vector always has the exact buffer length");

        Ok(Self::from_parts(
            BtcParams::from(Params::from(network)),
            delegate.last_verified_block,
            delegate.next_block_target,
            delegate.epoch_start_timestamp,
            TimestampStore::from_parts(buffer, head),
            BtcWork::from_le_bytes(delegate.total_accumulated_pow.to_le_bytes::<32>()),
        ))
    }
}

impl_ssz_via_delegate!(HeaderVerificationState);

impl SszTypeInfo for HeaderVerificationState {
    fn is_ssz_fixed_len() -> bool {
        <HeaderVerificationStateSsz as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <HeaderVerificationStateSsz as ssz::Encode>::ssz_fixed_len()
    }
}

/// Decoded view over the SSZ bytes of a [`HeaderVerificationState`].
///
/// ssz-gen requires external container types to expose a `{Type}Ref` view.
/// The delegate encoding has no zero-copy representation, so this view
/// decodes eagerly and hands out the owned value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderVerificationStateRef<'a> {
    inner: HeaderVerificationState,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> DecodeView<'a> for HeaderVerificationStateRef<'a> {
    fn from_ssz_bytes(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            inner: <HeaderVerificationState as Decode>::from_ssz_bytes(bytes)?,
            _phantom: PhantomData,
        })
    }
}

impl SszTypeInfo for HeaderVerificationStateRef<'_> {
    fn is_ssz_fixed_len() -> bool {
        <HeaderVerificationState as SszTypeInfo>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <HeaderVerificationState as SszTypeInfo>::ssz_fixed_len()
    }
}

impl tree_hash::TreeHash for HeaderVerificationStateRef<'_> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <HeaderVerificationState as tree_hash::TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.inner.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <HeaderVerificationState as tree_hash::TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root<H: tree_hash::TreeHashDigest>(&self) -> H::Output {
        self.inner.tree_hash_root::<H>()
    }
}

impl ToOwnedSsz<HeaderVerificationState> for HeaderVerificationStateRef<'_> {
    fn to_owned(&self) -> HeaderVerificationState {
        self.inner.clone()
    }
}

#[cfg(test)]
mod tests {
    use ssz::Encode;
    use strata_identifiers::L1BlockCommitment;
    use tree_hash::TreeHash;

    use super::*;
    use crate::L1Anchor;

    fn sample_state() -> HeaderVerificationState {
        let anchor = L1Anchor {
            block: L1BlockCommitment::default(),
            next_target: 0x1d00ffff,
            epoch_start_timestamp: 1_231_006_505,
            network: Network::Bitcoin,
        };
        HeaderVerificationState::init(anchor)
    }

    #[test]
    fn ssz_roundtrip() {
        let state = sample_state();
        let bytes = state.as_ssz_bytes();
        let decoded = HeaderVerificationState::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(state, decoded);
    }

    #[test]
    fn view_roundtrip() {
        let state = sample_state();
        let bytes = state.as_ssz_bytes();
        let view = HeaderVerificationStateRef::from_ssz_bytes(&bytes).expect("view decode");
        assert_eq!(ToOwnedSsz::to_owned(&view), state);
        assert_eq!(
            view.tree_hash_root::<tree_hash::Sha256Hasher>(),
            state.tree_hash_root::<tree_hash::Sha256Hasher>()
        );
    }

    #[test]
    fn decode_rejects_unknown_network() {
        let mut bytes = sample_state().as_ssz_bytes();
        // The network id is the first byte of the fixed-size container.
        bytes[0] = 42;
        assert!(HeaderVerificationState::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_out_of_bounds_head() {
        let state = sample_state();
        let mut delegate = state.into_delegate();
        delegate.block_timestamp_history.head = TIMESTAMPS_FOR_MEDIAN as u8;
        let bytes = delegate.as_ssz_bytes();
        assert!(HeaderVerificationState::from_ssz_bytes(&bytes).is_err());
    }
}
