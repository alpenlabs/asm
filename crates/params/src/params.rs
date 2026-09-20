#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use serde::{Deserialize, Serialize};
use strata_asm_admin_types::AdministrationInitConfig;
use strata_asm_bridge_types::BridgeInitConfig;
use strata_asm_checkpoint_types::CheckpointInitConfig;
use strata_btc_verification::L1Anchor;
use strata_l1_txfmt::MagicBytes;

/// A configured subprotocol that can be registered in [`AsmParams`].
///
/// Each variant carries the configuration for a single ASM subprotocol.
/// The list of instances stored in `AsmParams` determines which subprotocols
/// are active for a given network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubprotocolInstance {
    /// Administration subprotocol for system upgrades.
    Admin(AdministrationInitConfig),

    /// Bridge V1 subprotocol for deposit/withdrawal management.
    Bridge(BridgeInitConfig),

    /// Checkpoint subprotocol for OL checkpoint verification.
    Checkpoint(CheckpointInitConfig),
}

/// Top-level parameters for an ASM instance.
///
/// Combines the SPS-50 magic bytes used to tag L1 transactions, the genesis
/// L1 view that bootstraps header verification, and the set of active
/// subprotocol configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmParams {
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

impl AsmParams {
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
impl<'a> Arbitrary<'a> for AsmParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        use strata_identifiers::L1BlockCommitment;

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
                SubprotocolInstance::Admin(AdministrationInitConfig::arbitrary_for_network(
                    u, network,
                )?),
                SubprotocolInstance::Checkpoint(CheckpointInitConfig::arbitrary(u)?),
                SubprotocolInstance::Bridge(BridgeInitConfig::arbitrary(u)?),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::regtest_params_json;

    #[test]
    fn test_asm_params_deserialize_from_raw_json() {
        let raw_json = regtest_params_json();

        let params: AsmParams =
            serde_json::from_str(raw_json).expect("deserialization from raw JSON should succeed");

        // Signers are written as addresses on the anchor's network, so resolving them is
        // part of what the fixture pins: a params file that mixes networks would fail here.
        // The anchor is on regtest and the signers are written as regtest addresses, which
        // is exactly what `verify` is there to confirm.
        params
            .verify()
            .expect("signer addresses match the anchor network");

        let admin = params.admin_config().expect("params carry an Admin config");
        assert_eq!(admin.strata_sequencer_manager.signers().len(), 2);
    }

    #[cfg(feature = "arbitrary")]
    mod proptest_arbitrary {
        use arbitrary::{Arbitrary, Unstructured};
        use proptest::{collection, prelude::*};

        use super::*;

        proptest! {
            #[test]
            fn test_arbitrary(seed in collection::vec(any::<u8>(), 0..4096)) {
                let mut u = Unstructured::new(&seed);
                let res = AsmParams::arbitrary(&mut u);
                prop_assert!(res.is_ok());
            }
        }
    }
}
