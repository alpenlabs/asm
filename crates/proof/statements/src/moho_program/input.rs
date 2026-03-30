//! Input types for the ASM STF Moho program.
//!
//! This module defines [`AsmStepInput`], the per-step input consumed by the
//! [`MohoProgram`](moho_runtime_interface::MohoProgram) implementation.
use bitcoin::{hashes::Hash, Block};
use moho_types::StateReference;
use ssz_derive::{Decode, Encode};
use strata_asm_common::AuxData;
use strata_btc_verification::{compute_block_hash, TxidInclusionProof};

/// Private input for a single ASM STF step.
///
/// Contains the full L1 Bitcoin block and auxiliary data required to execute the state
/// transition.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct AsmStepInput {
    /// Consensus-encoded Bitcoin block bytes.
    #[ssz(with = "block_ssz")]
    block: Block,
    /// SSZ-encoded auxiliary data required to run the ASM STF.
    aux_data: AuxData,
    /// Optional txid inclusion proof for the coinbase transaction.
    coinbase_inclusion_proof: Option<TxidInclusionProof>,
}

impl AsmStepInput {
    /// Creates a new Moho step input.
    pub fn new(
        block: Block,
        aux_data: AuxData,
        coinbase_inclusion_proof: Option<TxidInclusionProof>,
    ) -> Self {
        Self {
            block,
            aux_data,
            coinbase_inclusion_proof,
        }
    }

    /// Returns the block being processed
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Returns the auxiliary data required for the ASM STF.
    pub fn aux_data(&self) -> &AuxData {
        &self.aux_data
    }

    /// Computes the state reference.
    ///
    /// In concrete terms, this just computes the blkid/blockhash.
    pub fn compute_ref(&self) -> StateReference {
        let raw_ref = compute_block_hash(&self.block.header);
        StateReference::new(raw_ref.to_byte_array())
    }

    /// Computes the previous state reference from the input.
    ///
    /// In concrete terms, this just extracts the parent blkid from the block's
    /// header.
    pub fn compute_prev_ref(&self) -> StateReference {
        let parent_ref = self.block.header.prev_blockhash.to_byte_array();
        StateReference::new(parent_ref)
    }

    /// Returns the optional coinbase inclusion proof.
    pub fn coinbase_inclusion_proof(&self) -> Option<&TxidInclusionProof> {
        self.coinbase_inclusion_proof.as_ref()
    }
}
#[expect(unreachable_pub, reason = "used by ssz_derive field adapters")]
mod block_ssz {
    use bitcoin::{
        consensus::{deserialize, serialize},
        Block,
    };

    pub mod encode {
        use ssz::Encode as SszEncode;

        use super::{serialize, Block};

        pub fn is_ssz_fixed_len() -> bool {
            <Vec<u8> as SszEncode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <Vec<u8> as SszEncode>::ssz_fixed_len()
        }

        pub fn ssz_bytes_len(value: &Block) -> usize {
            serialize(value).ssz_bytes_len()
        }

        pub fn ssz_append(value: &Block, buf: &mut Vec<u8>) {
            serialize(value).ssz_append(buf);
        }
    }

    pub mod decode {
        use ssz::{Decode as SszDecode, DecodeError};

        use super::{deserialize, Block};

        pub fn is_ssz_fixed_len() -> bool {
            <Vec<u8> as SszDecode>::is_ssz_fixed_len()
        }

        pub fn ssz_fixed_len() -> usize {
            <Vec<u8> as SszDecode>::ssz_fixed_len()
        }

        pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Block, DecodeError> {
            let raw = Vec::<u8>::from_ssz_bytes(bytes)?;
            deserialize(&raw).map_err(|err| DecodeError::BytesInvalid(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};
    use strata_test_utils_btc::BtcMainnetSegment;

    use super::*;

    #[test]
    fn test_ssz_roundtrip() {
        let block = BtcMainnetSegment::load_full_block();
        let input = AsmStepInput::new(block, AuxData::new(vec![], vec![]), None);

        let serialized = input.as_ssz_bytes();
        let decoded = AsmStepInput::from_ssz_bytes(&serialized).unwrap();

        assert_eq!(input.block(), decoded.block());
        assert_eq!(input.aux_data(), decoded.aux_data());
    }
}
