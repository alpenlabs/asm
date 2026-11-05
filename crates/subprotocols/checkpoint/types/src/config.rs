#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use strata_identifiers::{Buf32, L1Height, OLBlockId};
use strata_predicate::PredicateKey;
use thiserror::Error;

/// Checkpoint subprotocol initialization configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct CheckpointInitConfig {
    /// X-only BIP340 Schnorr key that must sign the checkpoint envelope.
    pub sequencer_key: Buf32,
    /// Predicate for checkpoint ZK proof verification.
    pub checkpoint_predicate: PredicateKey,
    /// Genesis L1 block height.
    ///
    /// Must equal the height of the ASM's L1 anchor; see
    /// [`check_genesis_l1_height`](Self::check_genesis_l1_height).
    pub genesis_l1_height: L1Height,
    /// Genesis OL block ID.
    pub genesis_ol_blkid: OLBlockId,
}

impl CheckpointInitConfig {
    /// Checks that the genesis L1 height is the height of the anchor the ASM starts from.
    ///
    /// The genesis verified tip takes its L1 height from this config, while the manifest
    /// history accumulator and the header verification state take theirs from the anchor.
    /// Checkpoint coverage starts one block after the verified tip's height, so if the two
    /// disagree, the first checkpoint asks for manifests the accumulator does not hold at
    /// those positions. A height above every reachable L1 tip leaves no checkpoint that can
    /// ever be accepted.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointGenesisHeightMismatch`] if the heights differ.
    pub fn check_genesis_l1_height(
        &self,
        anchor_height: L1Height,
    ) -> Result<(), CheckpointGenesisHeightMismatch> {
        if self.genesis_l1_height == anchor_height {
            Ok(())
        } else {
            Err(CheckpointGenesisHeightMismatch {
                checkpoint_height: self.genesis_l1_height,
                anchor_height,
            })
        }
    }
}

/// A checkpoint genesis L1 height that differs from the height of the ASM's L1 anchor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "checkpoint genesis L1 height {checkpoint_height} does not match the L1 anchor height {anchor_height}"
)]
pub struct CheckpointGenesisHeightMismatch {
    /// Genesis L1 height in the checkpoint configuration.
    checkpoint_height: L1Height,
    /// Height of the L1 anchor.
    anchor_height: L1Height,
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateKey;

    use super::*;

    fn config_at_height(genesis_l1_height: L1Height) -> CheckpointInitConfig {
        CheckpointInitConfig {
            sequencer_key: Buf32::zero(),
            checkpoint_predicate: PredicateKey::always_accept(),
            genesis_l1_height,
            genesis_ol_blkid: OLBlockId::null(),
        }
    }

    #[test]
    fn check_genesis_l1_height_accepts_anchor_height() {
        assert_eq!(config_at_height(100).check_genesis_l1_height(100), Ok(()));
    }

    #[test]
    fn check_genesis_l1_height_rejects_other_height() {
        assert_eq!(
            config_at_height(u32::MAX)
                .check_genesis_l1_height(100)
                .unwrap_err()
                .to_string(),
            "checkpoint genesis L1 height 4294967295 does not match the L1 anchor height 100"
        );
    }
}
