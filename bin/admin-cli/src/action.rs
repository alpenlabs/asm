//! The admin actions the CLI can sign and submit.

use std::str::FromStr;

use anyhow::{Context, ensure};
use bitcoin::{
    Address, Network,
    address::NetworkUnchecked,
    secp256k1::{self, PublicKey, XOnlyPublicKey},
};
use clap::Subcommand;
use strata_asm_bridge_types::SafeHarborAddress;
use strata_asm_proto_admin_txs::actions::{
    CancelAction, MultisigAction, UpdateAction, UpdateId,
    updates::{
        AsmStfVkUpdate, EeStfVkUpdate, OlStfVkUpdate, OperatorSetUpdate, SafeHarborAddressUpdate,
    },
};
use strata_crypto::EvenPublicKey;
use strata_predicate::PredicateKey;

/// An admin action, given as the last subcommand of every command.
#[derive(Debug, Subcommand)]
pub(crate) enum ActionCmd {
    #[command(flatten)]
    Update(UpdateCmd),
    /// Cancel a queued update before it activates.
    ///
    /// Describe the update exactly as it was queued. The chain rebuilds the signing message
    /// from its own copy, so signatures over any other update fail.
    Cancel {
        /// ID the update was queued under.
        #[arg(long)]
        id: UpdateId,
        #[command(subcommand)]
        update: UpdateCmd,
    },
}

/// An update to propose, or the queued update a cancel targets.
#[derive(Debug, Subcommand)]
pub(crate) enum UpdateCmd {
    /// Set the ASM STF predicate, which selects the ASM spec.
    ///
    /// Every ASM executor must already list the new predicate, or it halts at the first
    /// block after the update activates.
    AsmStfVk {
        /// New predicate, e.g. `Sp1Groth16:<hex>`.
        #[arg(long)]
        predicate: PredicateKey,
    },
    /// Set the OL STF (checkpoint) predicate.
    OlStfVk {
        /// New predicate, e.g. `Sp1Groth16:<hex>`.
        #[arg(long)]
        predicate: PredicateKey,
    },
    /// Set the EE STF predicate.
    EeStfVk {
        /// New predicate, e.g. `Sp1Groth16:<hex>`.
        #[arg(long)]
        predicate: PredicateKey,
    },
    /// Rotate the bridge's safe harbor address.
    SafeHarbor {
        /// New P2TR address, as a wallet shows it.
        #[arg(long)]
        address: Address<NetworkUnchecked>,
    },
    /// Add and remove bridge operators.
    ///
    /// To rotate an operator's key, remove its index and add the new key. The bridge ignores
    /// a key it has ever held, so a removed key can't be added back.
    OperatorSet {
        /// MuSig2 key of an operator to add, as compressed hex like the params file or as
        /// 32-byte x-only hex. Repeat for each operator.
        #[arg(
            long = "add",
            value_name = "KEY",
            value_parser = parse_operator_key,
            required_unless_present = "remove"
        )]
        add: Vec<EvenPublicKey>,
        /// Index of an operator to remove. Repeat for each operator.
        #[arg(long = "remove", value_name = "INDEX")]
        remove: Vec<u32>,
    },
}

impl ActionCmd {
    /// Builds the action for a chain on `network`.
    pub(crate) fn into_action(self, network: Network) -> anyhow::Result<MultisigAction> {
        Ok(match self {
            ActionCmd::Update(update) => MultisigAction::Update(update.into_update(network)?),
            ActionCmd::Cancel { id, update } => {
                MultisigAction::Cancel(CancelAction::new(id, update.into_update(network)?))
            }
        })
    }
}

impl UpdateCmd {
    fn into_update(self, network: Network) -> anyhow::Result<UpdateAction> {
        Ok(match self {
            UpdateCmd::AsmStfVk { predicate } => {
                UpdateAction::AsmStfVk(AsmStfVkUpdate::new(predicate))
            }
            UpdateCmd::OlStfVk { predicate } => {
                UpdateAction::OlStfVk(OlStfVkUpdate::new(predicate))
            }
            UpdateCmd::EeStfVk { predicate } => {
                UpdateAction::EeStfVk(EeStfVkUpdate::new(predicate))
            }
            UpdateCmd::SafeHarbor { address } => {
                // The action stores only the output key, so an address from another network
                // would still be accepted. Catch the paste mistake here instead.
                ensure!(
                    address.is_valid_for_network(network),
                    "safe harbor address is not a {network} address"
                );
                let address = SafeHarborAddress::try_from_address(&address)
                    .context("invalid safe harbor address")?;
                UpdateAction::SafeHarborAddress(SafeHarborAddressUpdate::new(address))
            }
            UpdateCmd::OperatorSet { add, remove } => {
                UpdateAction::OperatorSet(OperatorSetUpdate::new(add, remove))
            }
        })
    }
}

/// Parses an operator key as compressed or x-only hex.
///
/// The chain keeps only the x coordinate, so an `03` key names the same operator as its `02`
/// twin.
fn parse_operator_key(s: &str) -> Result<EvenPublicKey, secp256k1::Error> {
    match XOnlyPublicKey::from_str(s) {
        Ok(key) => Ok(key.into()),
        Err(_) => PublicKey::from_str(s).map(Into::into),
    }
}
