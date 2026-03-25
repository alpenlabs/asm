//! L1 anchor point for bootstrapping Bitcoin L1 verification.
//!
//! See [`L1Anchor`] for details.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Result, Unstructured};
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use strata_identifiers::L1BlockCommitment;

/// Snapshot of L1 chain state used to anchor the ASM to a known point on the Bitcoin chain.
///
/// This struct holds the minimum information required to resume L1 verification from an
/// arbitrary point: which block was last verified, what difficulty target the next block must
/// satisfy, when the current difficulty-adjustment epoch began, and which network's consensus
/// rules apply.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct L1Anchor {
    /// Commitment (height + block hash) to the last verified L1 block.
    pub block: L1BlockCommitment,

    /// Compact-encoded target that the next block header must satisfy.
    pub next_target: u32,

    /// Timestamp of the first block in the current difficulty-adjustment epoch.
    pub epoch_start_timestamp: u32,

    /// Bitcoin network (mainnet, testnet, signet, regtest) that determines consensus parameters.
    pub network: Network,
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for L1Anchor {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let network = *u.choose(&[
            Network::Bitcoin,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ])?;

        Ok(Self {
            block: u.arbitrary()?,
            next_target: u.arbitrary()?,
            epoch_start_timestamp: u.arbitrary()?,
            network,
        })
    }
}
