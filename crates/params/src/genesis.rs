//! Parameters consumed once, at genesis state construction.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use serde::{Deserialize, Serialize};
use strata_btc_verification::L1Anchor;
#[cfg(feature = "arbitrary")]
use strata_identifiers::L1BlockCommitment;
use strata_l1_txfmt::MagicBytes;

use crate::subprotocols::{
    AdministrationInitConfig, BridgeInitConfig, CheckpointInitConfig, SubprotocolInstance,
};

/// Parameters used to construct the genesis anchor state.
///
/// Combines the SPS-50 magic bytes used to tag L1 transactions, the genesis
/// L1 view that bootstraps header verification, and the set of active
/// subprotocol configurations. After genesis everything here lives on in the
/// anchor state itself; the STF never reads these again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmGenesisParams {
    /// SPS-50 magic bytes that identify protocol transactions on L1.
    pub magic: MagicBytes,

    /// L1 anchor point after which L1 processing begins.
    ///
    /// Captures everything needed to initialize
    /// [`HeaderVerificationState`](strata_btc_verification::HeaderVerificationState) and
    /// begin validating subsequent L1 headers.
    pub anchor: L1Anchor,

    /// Ordered list of subprotocol configurations active in this ASM.
    pub subprotocols: Vec<SubprotocolInstance>,
}

impl AsmGenesisParams {
    pub fn admin_config(&self) -> Option<&AdministrationInitConfig> {
        self.subprotocols.iter().find_map(|s| match s {
            SubprotocolInstance::Admin(cfg) => Some(cfg),
            _ => None,
        })
    }

    pub fn bridge_config(&self) -> Option<&BridgeInitConfig> {
        self.subprotocols.iter().find_map(|s| match s {
            SubprotocolInstance::Bridge(cfg) => Some(cfg),
            _ => None,
        })
    }

    pub fn checkpoint_config(&self) -> Option<&CheckpointInitConfig> {
        self.subprotocols.iter().find_map(|s| match s {
            SubprotocolInstance::Checkpoint(cfg) => Some(cfg),
            _ => None,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AsmGenesisParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let networks = [
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ];
        let network = *u.choose(&networks)?;

        let block = L1BlockCommitment::arbitrary(u)?;
        let anchor = L1Anchor {
            block,
            next_target: u.arbitrary()?,
            epoch_start_timestamp: u.arbitrary()?,
            network,
        };

        Ok(Self {
            magic: MagicBytes::new(*b"ALPN"),
            anchor,
            subprotocols: vec![
                SubprotocolInstance::Admin(AdministrationInitConfig::arbitrary(u)?),
                SubprotocolInstance::Checkpoint(CheckpointInitConfig::arbitrary(u)?),
                SubprotocolInstance::Bridge(BridgeInitConfig::arbitrary(u)?),
            ],
        })
    }
}
