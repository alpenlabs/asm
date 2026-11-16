//! The admin actions the CLI can sign and submit.

use anyhow::{Context, ensure};
use bitcoin::{Address, Network, address::NetworkUnchecked};
use clap::Subcommand;
use strata_asm_bridge_types::SafeHarborAddress;
use strata_asm_proto_admin_txs::actions::{
    CancelAction, MultisigAction, UpdateAction, UpdateId,
    updates::{AsmStfVkUpdate, EeStfVkUpdate, OlStfVkUpdate, SafeHarborAddressUpdate},
};
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
        })
    }
}
