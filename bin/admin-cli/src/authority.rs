//! The chain and signer set an action is checked against, and the check itself.

use std::{fs, num::NonZero, path::PathBuf, slice};

use anyhow::{Context, anyhow, ensure};
use bitcoin::{Address, Network, address::NetworkUnchecked};
use clap::Args;
use strata_asm_admin_threshold_sig::{
    IndexedSignature, SignatureSet, ThresholdConfig, ThresholdSignatureError,
    verify_threshold_signatures,
};
use strata_asm_admin_types::{AdministrationInitConfig, Role, UncheckedThresholdConfig};
use strata_asm_params::AsmParams;
use strata_l1_txfmt::MagicBytes;

/// Where the chain's network, magic and signer set come from.
///
/// Either the params file the chain was launched with, or all of them by hand. The params
/// file holds the genesis signer sets, so a role whose signers were rotated on chain needs
/// the explicit form.
#[derive(Debug, Args)]
pub(crate) struct AuthorityArgs {
    /// ASM params file the chain was launched with.
    #[arg(
        long,
        required_unless_present = "signer",
        conflicts_with_all = ["network", "magic", "signer", "threshold"],
    )]
    params: Option<PathBuf>,

    /// Bitcoin network the chain is anchored to.
    #[arg(long, requires = "signer")]
    network: Option<Network>,

    /// SPS-50 magic bytes the chain was launched with.
    #[arg(long, requires = "signer")]
    magic: Option<MagicBytes>,

    /// P2WPKH address of a signer of the role, in signer-index order. Repeat for each signer.
    #[arg(long, requires_all = ["network", "magic", "threshold"])]
    signer: Vec<Address<NetworkUnchecked>>,

    /// Number of signatures the role needs.
    #[arg(long, requires = "signer")]
    threshold: Option<NonZero<u8>>,
}

/// The chain an action is submitted to, and where its signer sets come from.
#[derive(Debug)]
pub(crate) struct Chain {
    pub(crate) network: Network,
    pub(crate) magic: MagicBytes,
    signers: Signers,
}

#[derive(Debug)]
enum Signers {
    /// Every role's genesis signer set.
    Genesis(AdministrationInitConfig),
    /// One signer set, used for whichever role the action needs.
    Explicit(ThresholdConfig),
}

impl Chain {
    /// The signer set `role` needs.
    pub(crate) fn signers(&self, role: Role) -> ThresholdConfig {
        match &self.signers {
            Signers::Genesis(admin) => {
                let (_, unchecked) = admin
                    .signer_configs()
                    .into_iter()
                    .find(|(r, _)| *r == role)
                    .expect("every role has a signer config");
                ThresholdConfig::try_from(unchecked)
                    .expect("a parsed config passed the same validation")
            }
            Signers::Explicit(config) => config.clone(),
        }
    }
}

impl AuthorityArgs {
    /// Loads the chain's network, magic and signer sets.
    pub(crate) fn load(&self) -> anyhow::Result<Chain> {
        match &self.params {
            Some(path) => {
                let json = fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                chain_from_params(&json).with_context(|| format!("params file {}", path.display()))
            }
            None => {
                // clap enforces that the explicit form is complete.
                let network = self.network.expect("clap requires --network");
                let magic = self.magic.expect("clap requires --magic");
                let threshold = self.threshold.expect("clap requires --threshold");
                for (index, signer) in self.signer.iter().enumerate() {
                    ensure!(
                        signer.is_valid_for_network(network),
                        "signer {index} is not a {network} address"
                    );
                }
                let unchecked = UncheckedThresholdConfig::try_new(self.signer.clone(), threshold)
                    .context("invalid signer set")?;
                let config =
                    ThresholdConfig::try_from(&unchecked).expect("try_new ran the same validation");
                Ok(Chain {
                    network,
                    magic,
                    signers: Signers::Explicit(config),
                })
            }
        }
    }
}

fn chain_from_params(json: &str) -> anyhow::Result<Chain> {
    let params: AsmParams = serde_json::from_str(json).context("failed to parse")?;
    let genesis = params.genesis;
    let network = genesis.anchor.network;
    let admin = genesis
        .admin_config()
        .context("no Admin subprotocol configured")?;
    admin.check_signer_networks(network)?;
    Ok(Chain {
        network,
        magic: genesis.magic,
        signers: Signers::Genesis(admin.clone()),
    })
}

/// Checks `signatures` over `digest` exactly as the chain does.
///
/// Each signature is first checked alone, so a failure names the signer it came from.
pub(crate) fn verify_signatures(
    config: &ThresholdConfig,
    network: Network,
    signatures: &[IndexedSignature],
    digest: &[u8; 32],
) -> anyhow::Result<SignatureSet> {
    let set = SignatureSet::new(signatures.to_vec())?;
    let signers = config.signers();
    let any_one = ThresholdConfig::try_new(signers.to_vec(), NonZero::<u8>::MIN)
        .expect("a subset of a valid config is valid");
    for signature in signatures {
        let index = signature.index();
        let signer = signers.get(usize::from(index)).ok_or_else(|| {
            anyhow!(
                "signer index {index} is out of range: the role has {} signers",
                signers.len()
            )
        })?;
        verify_threshold_signatures(&any_one, slice::from_ref(signature), digest).map_err(
            |err| match err {
                ThresholdSignatureError::NonCanonicalSignature { .. } => anyhow!(
                    "signature {index} has a zero r or s, or a high s, which the chain refuses; \
                     sign again with a wallet that emits low-s signatures"
                ),
                _ => anyhow!(
                    "signature {index} is not from signer {} over this message",
                    signer.to_address(network)
                ),
            },
        )?;
    }
    verify_threshold_signatures(config, signatures, digest)?;
    Ok(set)
}
