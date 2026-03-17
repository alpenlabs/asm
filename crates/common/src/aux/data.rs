//! Auxiliary request and response data.
//!
//! Defines the types of auxiliary data that subprotocols can request during
//! the pre-processing phase, along with the response structures returned
//! to subprotocols after verification.
use bitcoin::{
    Transaction, Txid,
    consensus::{deserialize, encode::Error as ConsensusEncodeError, serialize},
    hashes::Hash,
};
use ssz_derive::{Decode, Encode};
use strata_asm_manifest_types::Hash32;

use crate::AsmMerkleProof;

#[doc(hidden)]
pub trait IntoAsmMerkleProof {
    fn into_asm_merkle_proof(self) -> AsmMerkleProof;
}

impl IntoAsmMerkleProof for AsmMerkleProof {
    fn into_asm_merkle_proof(self) -> AsmMerkleProof {
        self
    }
}

impl IntoAsmMerkleProof for strata_merkle::MerkleProof<[u8; 32]> {
    fn into_asm_merkle_proof(self) -> AsmMerkleProof {
        AsmMerkleProof::from_cohashes(self.cohashes().to_vec(), self.index())
    }
}

/// Collection of auxiliary data requests from subprotocols.
///
/// During pre-processing, subprotocols declare what auxiliary data they need.
/// External workers fulfill that before the main processing phase.
#[derive(Debug, Clone, Default, Encode, Decode)]
pub struct AuxRequests {
    /// Requested manifest hash height ranges.
    pub(crate) manifest_hashes: Vec<ManifestHashRange>,

    /// [Txid](bitcoin::Txid) of the requested transactions.
    pub(crate) bitcoin_txs: Vec<BitcoinTxid>,
}

impl AuxRequests {
    /// Returns a slice of the requested manifest hash ranges.
    pub fn manifest_hashes(&self) -> &[ManifestHashRange] {
        &self.manifest_hashes
    }

    /// Returns a slice of the requested Bitcoin transaction IDs.
    pub fn bitcoin_txs(&self) -> &[BitcoinTxid] {
        &self.bitcoin_txs
    }
}

/// Collection of auxiliary data responses for subprotocols.
///
/// Contains unverified Bitcoin transactions and manifest hashes returned by external workers.
/// This data must be validated before use during the main processing phase.
#[derive(Debug, Clone, Default, PartialEq, Encode, Decode)]
pub struct AuxData {
    /// Manifest hashes with their MMR proofs (unverified)
    manifest_hashes: Vec<VerifiableManifestHash>,
    /// Raw Bitcoin transaction data (unverified)
    bitcoin_txs: Vec<RawBitcoinTx>,
}

impl AuxData {
    /// Creates a new auxiliary data collection.
    pub fn new(
        manifest_hashes: Vec<VerifiableManifestHash>,
        bitcoin_txs: Vec<RawBitcoinTx>,
    ) -> Self {
        Self {
            manifest_hashes,
            bitcoin_txs,
        }
    }

    /// Returns a slice of manifest hashes with their MMR proofs.
    pub fn manifest_hashes(&self) -> &[VerifiableManifestHash] {
        &self.manifest_hashes
    }

    /// Returns a slice of raw Bitcoin transactions.
    pub fn bitcoin_txs(&self) -> &[RawBitcoinTx] {
        &self.bitcoin_txs
    }
}

/// Manifest hash height range (inclusive).
///
/// Represents a range of L1 block heights for which manifest hashes are requested.
#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct ManifestHashRange {
    /// Start height (inclusive)
    pub(crate) start_height: u64,
    /// End height (inclusive)
    pub(crate) end_height: u64,
}

impl ManifestHashRange {
    /// Creates a new manifest hash range.
    pub fn new(start_height: u64, end_height: u64) -> Self {
        Self {
            start_height,
            end_height,
        }
    }

    /// Returns the start height (inclusive).
    pub fn start_height(&self) -> u64 {
        self.start_height
    }

    /// Returns the end height (inclusive).
    pub fn end_height(&self) -> u64 {
        self.end_height
    }
}

/// Manifest hash with its MMR proof.
///
/// Contains a hash of an [`AsmManifest`](crate::AsmManifest) along with an MMR proof
/// that can be used to verify the hash's inclusion in the manifest MMR at a specific position.
///
/// This is unverified data - the proof must be verified against a trusted compact MMR
/// before the hash can be considered valid.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct VerifiableManifestHash {
    /// The hash of an [`AsmManifest`](crate::AsmManifest)
    hash: Hash32,
    /// The MMR proof for this manifest hash
    proof: AsmMerkleProof,
}

impl VerifiableManifestHash {
    /// Creates a new verifiable manifest hash.
    pub fn new(hash: Hash32, proof: impl IntoAsmMerkleProof) -> Self {
        Self {
            hash,
            proof: proof.into_asm_merkle_proof(),
        }
    }

    /// Returns the manifest hash.
    pub fn hash(&self) -> &Hash32 {
        &self.hash
    }

    /// Returns a reference to the MMR proof.
    pub fn proof(&self) -> &AsmMerkleProof {
        &self.proof
    }
}

/// Bitcoin transaction identifier used by ASM auxiliary lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
pub struct BitcoinTxid {
    bytes: [u8; 32],
}

impl BitcoinTxid {
    /// Creates an ASM-local txid from the native Bitcoin txid wrapper.
    pub fn from_native(txid: strata_btc_types::BitcoinTxid) -> Self {
        Self {
            bytes: txid.inner().to_byte_array(),
        }
    }

    /// Converts the ASM-local txid back into the native Bitcoin txid wrapper.
    pub fn into_native(self) -> strata_btc_types::BitcoinTxid {
        Txid::from_byte_array(self.bytes).into()
    }
}

impl From<Txid> for BitcoinTxid {
    fn from(value: Txid) -> Self {
        strata_btc_types::BitcoinTxid::new(&value).into()
    }
}

impl From<strata_btc_types::BitcoinTxid> for BitcoinTxid {
    fn from(value: strata_btc_types::BitcoinTxid) -> Self {
        Self::from_native(value)
    }
}

impl From<BitcoinTxid> for strata_btc_types::BitcoinTxid {
    fn from(value: BitcoinTxid) -> Self {
        value.into_native()
    }
}

/// Raw serialized Bitcoin transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct RawBitcoinTx {
    bytes: Vec<u8>,
}

impl RawBitcoinTx {
    /// Creates an ASM-local raw Bitcoin transaction from raw bytes.
    pub fn from_raw_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw transaction bytes.
    pub fn as_raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the wrapper and returns the raw bytes.
    pub fn into_raw_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Creates an ASM-local raw Bitcoin transaction from the native wrapper.
    pub fn from_native(raw_tx: strata_btc_types::RawBitcoinTx) -> Self {
        let tx = Transaction::try_from(&raw_tx)
            .expect("asm: native raw bitcoin tx should decode into a Bitcoin transaction");
        Self::from_raw_bytes(serialize(&tx))
    }

    /// Converts the ASM-local raw Bitcoin transaction back into the native wrapper.
    pub fn into_native(self) -> strata_btc_types::RawBitcoinTx {
        strata_btc_types::RawBitcoinTx::from_raw_bytes(self.into_raw_bytes())
    }
}

impl From<strata_btc_types::RawBitcoinTx> for RawBitcoinTx {
    fn from(value: strata_btc_types::RawBitcoinTx) -> Self {
        Self::from_native(value)
    }
}

impl From<RawBitcoinTx> for strata_btc_types::RawBitcoinTx {
    fn from(value: RawBitcoinTx) -> Self {
        value.into_native()
    }
}

impl TryFrom<&RawBitcoinTx> for Transaction {
    type Error = ConsensusEncodeError;

    fn try_from(value: &RawBitcoinTx) -> Result<Self, Self::Error> {
        deserialize(value.as_raw_bytes())
    }
}

impl TryFrom<RawBitcoinTx> for Transaction {
    type Error = ConsensusEncodeError;

    fn try_from(value: RawBitcoinTx) -> Result<Self, Self::Error> {
        deserialize(value.as_raw_bytes())
    }
}
