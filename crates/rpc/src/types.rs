//! Response types for the ASM RPC service.

use serde::{Deserialize, Serialize};
use strata_identifiers::Buf32;
use strata_merkle::MerkleProof;

/// An export leaf hash and its inclusion proof against the requested block's MMR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEntryWithProof {
    /// Hash stored at the requested export MMR index, not the original export payload.
    pub leaf_hash: Buf32,
    /// Inclusion proof for `leaf_hash` at the requested index.
    pub proof: MerkleProof<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use serde_json::{from_value, json, to_value};

    use super::*;

    #[test]
    fn export_entry_with_proof_json_roundtrip() {
        let response = ExportEntryWithProof {
            leaf_hash: Buf32::from([0xab; 32]),
            proof: MerkleProof::from_cohashes(vec![[0xcd; 32]], 3),
        };
        let value = to_value(&response).unwrap();
        assert_eq!(value["leaf_hash"], json!("ab".repeat(32)));
        assert!(value.get("proof").is_some());

        let decoded: ExportEntryWithProof = from_value(value).unwrap();
        assert_eq!(decoded.leaf_hash, response.leaf_hash);
        assert_eq!(decoded.proof.index(), response.proof.index());
        assert_eq!(decoded.proof.cohashes(), response.proof.cohashes());
    }
}
