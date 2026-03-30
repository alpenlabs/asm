//! Input types for the ASM STF Moho program.
//!
//! This module defines [`AsmStepInput`], the per-step input consumed by the
//! [`MohoProgram`](moho_runtime_interface::MohoProgram) implementation.
use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    Block,
};
use moho_types::StateReference;
use ssz_derive::{Decode, Encode};
use strata_asm_common::AuxData;
use strata_btc_verification::TxidInclusionProof;

/// Private input for a single ASM STF step.
///
/// Contains the full L1 Bitcoin block and auxiliary data required to execute the state
/// transition.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct AsmStepInput {
    /// Consensus-encoded Bitcoin block bytes.
    block_bytes: Vec<u8>,
    /// SSZ-encoded auxiliary data required to run the ASM STF.
    aux_data_bytes: Vec<u8>,
    /// Optional txid inclusion proof for the coinbase transaction.
    coinbase_inclusion_proof: Option<TxidInclusionProof>,
}

impl AsmStepInput {
    /// Creates a new Moho step input.
    pub fn new(
        block: L1Block,
        aux_data: AuxData,
        coinbase_inclusion_proof: Option<TxidInclusionProof>,
    ) -> Self {
        Self {
            block_bytes: serialize(&block.0),
            aux_data_bytes: ssz::Encode::as_ssz_bytes(&aux_data),
            coinbase_inclusion_proof,
        }
    }

    fn decode_block(&self) -> Block {
        deserialize(&self.block_bytes).expect("moho-program block bytes must remain valid")
    }

    /// Returns the full Bitcoin L1 block.
    ///
    /// This decodes `block_bytes` on every call. Callers that need multiple derived values from
    /// the same block should bind the returned `L1Block` once and reuse it.
    pub fn block(&self) -> L1Block {
        L1Block(self.decode_block())
    }

    /// Returns the auxiliary data required for the ASM STF.
    pub fn aux_data(&self) -> AuxData {
        <AuxData as ssz::Decode>::from_ssz_bytes(&self.aux_data_bytes)
            .expect("moho-program aux data bytes must remain valid")
    }

    /// Computes the state reference.
    ///
    /// In concrete terms, this just computes the blkid/blockhash.
    pub fn compute_ref(&self) -> StateReference {
        let raw_ref = self
            .decode_block()
            .block_hash()
            .to_raw_hash()
            .to_byte_array();
        StateReference::new(raw_ref)
    }

    /// Computes the previous state reference from the input.
    ///
    /// In concrete terms, this just extracts the parent blkid from the block's
    /// header.
    pub fn compute_prev_ref(&self) -> StateReference {
        let block = self.decode_block();
        let parent_ref = block.header.prev_blockhash.to_raw_hash().to_byte_array();
        StateReference::new(parent_ref)
    }

    /// Returns the optional coinbase inclusion proof.
    pub fn coinbase_inclusion_proof(&self) -> Option<&TxidInclusionProof> {
        self.coinbase_inclusion_proof.as_ref()
    }

    /// Checks that the block's merkle roots are consistent.
    pub fn validate_block(&self) -> bool {
        let block = self.decode_block();
        block.check_merkle_root() && block.check_witness_commitment()
    }
}

/// A wrapper around the full Bitcoin L1 block.
#[derive(Debug, Clone, PartialEq)]
pub struct L1Block(pub Block);

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};
    use strata_test_utils_btc::BtcMainnetSegment;

    use super::*;

    #[test]
    fn test_ssz_roundtrip() {
        let block = BtcMainnetSegment::load_full_block();
        let input = AsmStepInput::new(L1Block(block), AuxData::new(vec![], vec![]), None);

        let serialized = input.as_ssz_bytes();
        let decoded = AsmStepInput::from_ssz_bytes(&serialized).unwrap();

        assert_eq!(input.block(), decoded.block());
        assert_eq!(input.aux_data(), decoded.aux_data());
    }
}
