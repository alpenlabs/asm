//! Deposit request transaction building utilities

use arbitrary::{Arbitrary, Unstructured};
use strata_asm_bridge_types::{DepositDescriptor, DepositDescriptorError};
use strata_codec::VarVec;
use strata_l1_txfmt::TagData;
use thiserror::Error;

use crate::constants::{BRIDGE_SUBPROTOCOL_ID, BridgeTxType};

/// Maximum destination size in bytes.
///
/// SPS-50 defines a maximum OP_RETURN size of 80 bytes, which is split as:
/// - 4 bytes: magic
/// - 1 byte: subprotocol ID
/// - 1 byte: tx type
/// - 74 bytes: aux data (maximum)
///
/// Since aux data contains 32 bytes for recovery_pk, the maximum destination size is:
/// 74 - 32 = 42 bytes
///
/// Reference: <https://github.com/alpenlabs/strata-common/blob/93511df/crates/l1proto/txfmt/src/tag.rs>
const MAX_DESTINATION_LEN: usize = 42;

/// Error type for parsing deposit request auxiliary data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DrtHeaderAuxError {
    /// Auxiliary data is too short to contain recovery public key.
    #[error("auxiliary data too short: expected at least 32 bytes, got {0}")]
    TooShort(usize),

    /// Destination bytes exceed the maximum allowed length.
    #[error("destination too long: expected at most {expected} bytes, got {actual}")]
    DestinationTooLong { expected: usize, actual: usize },
}

/// Auxiliary data in the SPS-50 header for [`BridgeTxType::DepositRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrtHeaderAux {
    /// The depositor's public key used in the takeback script. If operators fail to process the
    /// deposit within the timeout period, the depositor can use the corresponding private key to
    /// reclaim their Bitcoin via the takeback tapscript.
    recovery_pk: [u8; 32],
    /// Destination specifying where BTC should be minted.
    ///
    /// Kept as raw bytes because consensus parsing accepts any destination that fits the
    /// SPS-50 budget; see [`Self::decode_destination`] for the admission-time descriptor syntax
    /// validation.
    destination: VarVec<u8>,
}

impl DrtHeaderAux {
    /// Creates new deposit request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination exceeds the maximum allowed length
    pub fn new(recovery_pk: [u8; 32], destination: VarVec<u8>) -> Result<Self, DrtHeaderAuxError> {
        if destination.len() > MAX_DESTINATION_LEN {
            return Err(DrtHeaderAuxError::DestinationTooLong {
                expected: MAX_DESTINATION_LEN,
                actual: destination.len(),
            });
        }

        Ok(Self {
            recovery_pk,
            destination,
        })
    }

    /// Creates deposit request metadata whose destination is the encoding of `descriptor`.
    ///
    /// Wallets should prefer this over [`Self::new`]: the resulting destination always passes
    /// descriptor syntax validation ([`Self::decode_destination`]). It does not make the
    /// destination routable: whether the named account exists is decided by the execution
    /// layer, which holds deposits to unknown accounts in limbo.
    pub fn from_descriptor(recovery_pk: [u8; 32], descriptor: &DepositDescriptor) -> Self {
        let destination = descriptor.encode_to_varvec();
        // An encoded descriptor is at most 36 bytes, well within the SPS-50 destination budget.
        debug_assert!(destination.len() <= MAX_DESTINATION_LEN);
        Self {
            recovery_pk,
            destination,
        }
    }

    /// Returns the recovery public key
    pub const fn recovery_pk(&self) -> &[u8; 32] {
        &self.recovery_pk
    }

    /// Returns the destination descriptor.
    pub fn destination(&self) -> &VarVec<u8> {
        &self.destination
    }

    /// Decodes the destination as a [`DepositDescriptor`], validating its syntax.
    ///
    /// This is the admission-time descriptor syntax validation for deposit requests. Operators
    /// must not sweep a request whose destination fails it: while the request is unswept, the
    /// depositor recovers the full amount through the takeback path once the recovery delay
    /// elapses. Success says nothing about whether the named account exists; that depends on
    /// execution-layer state.
    ///
    /// Consensus parsing ([`parse_drt`](super::parse_drt)) deliberately does not apply this
    /// check. When the ASM sees a deposit transaction the funds are already locked, so it records
    /// the deposit whatever its destination says and the execution layer accounts an
    /// undecodable destination as funds in limbo, rather than leaving a locked UTXO outside
    /// bridge accounting.
    ///
    /// # Errors
    ///
    /// Returns [`DepositDescriptorError`] if the destination is not a well-formed descriptor.
    pub fn decode_destination(&self) -> Result<DepositDescriptor, DepositDescriptorError> {
        DepositDescriptor::decode_from_slice(&self.destination)
    }

    /// Parses auxiliary data from a byte slice.
    pub fn from_aux_data(aux_data: &[u8]) -> Result<Self, DrtHeaderAuxError> {
        if aux_data.len() < 32 {
            return Err(DrtHeaderAuxError::TooShort(aux_data.len()));
        }

        let recovery_pk: [u8; 32] = aux_data[..32]
            .try_into()
            .expect("slice is exactly 32 bytes");
        let destination = aux_data[32..].to_vec();

        if destination.len() > MAX_DESTINATION_LEN {
            return Err(DrtHeaderAuxError::DestinationTooLong {
                expected: MAX_DESTINATION_LEN,
                actual: destination.len(),
            });
        }

        let destination = VarVec::from_vec(destination).expect("valid destination");

        Ok(Self {
            recovery_pk,
            destination,
        })
    }

    /// Builds a `TagData` instance from this auxiliary data.
    ///
    /// This method encodes the auxiliary data and constructs the tag data for inclusion
    /// in the SPS-50 OP_RETURN output.
    ///
    /// # Panics
    ///
    /// Panics if encoding fails or if the encoded auxiliary data violates SPS-50 size
    /// limits.
    pub fn build_tag_data(&self) -> TagData {
        // Create aux data: first 32 bytes from recovery_pk, remaining bytes from destination
        let mut aux_data = Vec::with_capacity(32 + self.destination.len());
        aux_data.extend_from_slice(&self.recovery_pk);
        aux_data.extend_from_slice(&self.destination);

        TagData::new(
            BRIDGE_SUBPROTOCOL_ID,
            BridgeTxType::DepositRequest as u8,
            aux_data,
        )
        .expect("deposit request tag data should always fit within SPS-50 limits")
    }
}

impl<'a> Arbitrary<'a> for DrtHeaderAux {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut recovery_pk = [0u8; 32];
        u.fill_buffer(&mut recovery_pk)?;

        let destination_len = u.int_in_range(0..=MAX_DESTINATION_LEN)?;
        let mut destination_bytes = vec![0u8; destination_len];
        u.fill_buffer(&mut destination_bytes)?;

        let destination =
            VarVec::from_vec(destination_bytes).expect("destination is within bounds");

        Ok(Self {
            recovery_pk,
            destination,
        })
    }
}

#[cfg(test)]
mod tests {
    use strata_identifiers::{AccountSerial, SubjectIdBytes};

    use super::*;

    const RECOVERY_PK: [u8; 32] = [7; 32];

    fn aux_with_destination(destination: Vec<u8>) -> DrtHeaderAux {
        let destination = VarVec::from_vec(destination).expect("destination fits a VarVec");
        DrtHeaderAux::new(RECOVERY_PK, destination).expect("destination within SPS-50 budget")
    }

    fn descriptor(serial: u32, subject: Vec<u8>) -> DepositDescriptor {
        let subject = SubjectIdBytes::try_new(subject).expect("subject length is within bounds");
        DepositDescriptor::new(AccountSerial::new(serial), subject).expect("serial is encodable")
    }

    #[test]
    fn from_descriptor_destination_decodes_to_same_descriptor() {
        let cases = [
            descriptor(0, vec![]),
            descriptor(1, vec![0xaa; 20]),
            descriptor(268_435_455, vec![0x11; 32]),
        ];
        for expected in cases {
            let aux = DrtHeaderAux::from_descriptor(RECOVERY_PK, &expected);
            assert_eq!(&aux.destination()[..], expected.encode_to_vec());
            assert_eq!(aux.decode_destination(), Ok(expected.clone()));

            // The destination survives the SPS-50 tag round trip used by `parse_drt`.
            let tag = aux.build_tag_data();
            let parsed = DrtHeaderAux::from_aux_data(tag.aux_data()).expect("valid aux parses");
            assert_eq!(parsed.decode_destination(), Ok(expected));
        }
    }

    #[test]
    fn decode_destination_rejects_malformed_descriptors() {
        let cases: [(&str, Vec<u8>, DepositDescriptorError); 8] = [
            ("empty", vec![], DepositDescriptorError::EmptyDescriptor),
            (
                "control byte without serial byte",
                vec![0x00],
                DepositDescriptorError::InsufficientLength {
                    expected: 2,
                    actual: 1,
                },
            ),
            (
                "truncated 3-byte serial",
                vec![0x20, 0x01, 0x02],
                DepositDescriptorError::InsufficientLength {
                    expected: 4,
                    actual: 3,
                },
            ),
            (
                "reserved control bit 7",
                vec![0x80, 0x00],
                DepositDescriptorError::ReservedControlBits(0x80),
            ),
            (
                "reserved control bit 6",
                vec![0x40, 0x00],
                DepositDescriptorError::ReservedControlBits(0x40),
            ),
            (
                "reserved serial length",
                vec![0x30, 0x00, 0x00, 0x00, 0x00],
                DepositDescriptorError::ReservedSerialLengthBits(0x30),
            ),
            (
                "subject one byte too long",
                [vec![0x00, 0x00], vec![0x11; 33]].concat(),
                DepositDescriptorError::SubjectTooLong(33),
            ),
            (
                "maximum SPS-50 destination length",
                [vec![0x00, 0x00], vec![0x11; MAX_DESTINATION_LEN - 2]].concat(),
                DepositDescriptorError::SubjectTooLong(MAX_DESTINATION_LEN - 2),
            ),
        ];
        for (name, destination, expected) in cases {
            let aux = aux_with_destination(destination);
            assert_eq!(aux.decode_destination(), Err(expected), "{name}");
        }
    }

    /// Every destination longer than the longest descriptor fits the SPS-50 budget, so consensus
    /// parsing accepts it, yet admission must reject it.
    #[test]
    fn decode_destination_rejects_every_oversized_destination() {
        for len in 37..=MAX_DESTINATION_LEN {
            let aux = aux_with_destination(vec![0x00; len]);
            assert!(
                matches!(
                    aux.decode_destination(),
                    Err(DepositDescriptorError::SubjectTooLong(_))
                ),
                "destination length {len}"
            );
        }
    }
}
