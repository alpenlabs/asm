#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::{Deserialize, Serialize};
use strata_identifiers::{Buf32, L1Height, OLBlockId};
use strata_predicate::PredicateKey;

/// Checkpoint subprotocol initialization configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct CheckpointInitConfig {
    /// X-only BIP340 Schnorr key that must sign the checkpoint envelope.
    pub sequencer_key: Buf32,
    /// Predicate for checkpoint ZK proof verification.
    pub checkpoint_predicate: PredicateKey,
    /// Genesis L1 block height.
    pub genesis_l1_height: L1Height,
    /// Genesis OL block ID.
    pub genesis_ol_blkid: OLBlockId,
}
