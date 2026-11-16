//! Funds and broadcasts the admin transactions through a bitcoind wallet.

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::{FeeRate, Network, Transaction, consensus::encode::serialize_hex};
use bitcoind_async_client::{
    Auth, Client,
    corepc_types::v30::TestMempoolAccept,
    traits::{Broadcaster, Reader, Signer, Wallet},
    types::{CreateRawTransactionOutput, WalletCreateFundedPsbtOptions},
};
use clap::Args;
use serde_json::json;

use crate::envelope::Envelope;

/// The bitcoind wallet that pays for the admin transactions.
#[derive(Debug, Args)]
pub(crate) struct WalletArgs {
    /// bitcoind RPC URL of the funding wallet, e.g. `http://127.0.0.1:8332/wallet/<name>`.
    #[arg(long)]
    btc_url: String,

    /// bitcoind RPC user.
    #[arg(long, env = "BTC_RPC_USER")]
    btc_user: String,

    /// bitcoind RPC password.
    #[arg(long, env = "BTC_RPC_PASSWORD", hide_env_values = true)]
    btc_password: String,
}

impl WalletArgs {
    /// Connects to the wallet and checks that its node runs on `network`.
    pub(crate) async fn connect(&self, network: Network) -> anyhow::Result<Client> {
        let client = Client::new(
            self.btc_url.clone(),
            Auth::UserPass(self.btc_user.clone(), self.btc_password.clone()),
            None,
            None,
            None,
        )?;
        let node_network = client.network().await.context("failed to reach bitcoind")?;
        ensure!(
            node_network == network,
            "bitcoind runs on {node_network}, but the chain is anchored to {network}"
        );
        Ok(client)
    }
}

/// Funds a commit to `envelope` from the wallet and builds the reveal spending it.
///
/// Nothing is broadcast. The reveal's change goes back to the wallet.
pub(crate) async fn build_transactions(
    client: &Client,
    envelope: &Envelope,
    fee_rate: FeeRate,
) -> anyhow::Result<(Transaction, Transaction)> {
    let change = client.get_new_address().await?.script_pubkey();
    let value = envelope.commit_value(fee_rate, &change)?;
    let outputs = [CreateRawTransactionOutput::AddressAmount {
        address: envelope.address().to_string(),
        amount: value.to_btc(),
    }];
    let options = WalletCreateFundedPsbtOptions {
        fee_rate: Some(fee_rate),
        ..Default::default()
    };
    let funded = client
        .wallet_create_funded_psbt(&[], &outputs, None, Some(options), None)
        .await
        .context("the wallet could not fund the commit transaction")?;
    let signed = client
        .wallet_process_psbt(&funded.psbt.to_string(), Some(true), None, None)
        .await?;
    let commit = match signed.hex {
        Some(commit) if signed.complete => commit,
        _ => bail!("the wallet could not sign the commit transaction"),
    };
    let reveal = envelope.build_reveal(&commit, change, fee_rate)?;
    Ok((commit, reveal))
}

/// Checks that the node's mempool would take both transactions as a package.
pub(crate) async fn check_package(
    client: &Client,
    commit: &Transaction,
    reveal: &Transaction,
) -> anyhow::Result<()> {
    // The client's `test_mempool_accept` takes one transaction, and the reveal can't be
    // checked without its parent.
    let package = json!([serialize_hex(commit), serialize_hex(reveal)]);
    let result: TestMempoolAccept = client.call_raw("testmempoolaccept", &[package]).await?;
    let result = result
        .into_model()
        .map_err(|e| anyhow!("unexpected testmempoolaccept response: {e}"))?;
    ensure!(
        result.results.len() == 2,
        "bitcoind returned {} mempool results for 2 transactions",
        result.results.len()
    );
    for acceptance in &result.results {
        ensure!(
            acceptance.allowed,
            "bitcoind would reject {}: {}",
            acceptance.txid,
            acceptance
                .reject_reason
                .as_deref()
                .unwrap_or("no reason given")
        );
    }
    Ok(())
}

/// Broadcasts both transactions as one package, so the reveal doesn't wait for the commit
/// to reach the mempool.
pub(crate) async fn broadcast(
    client: &Client,
    commit: &Transaction,
    reveal: &Transaction,
) -> anyhow::Result<()> {
    let result = client
        .submit_package(&[commit.clone(), reveal.clone()], None)
        .await?;
    for tx in result.tx_results.values() {
        if let Some(error) = &tx.error {
            bail!("bitcoind rejected {}: {error}", tx.txid);
        }
    }
    ensure!(
        result.package_msg == "success",
        "bitcoind rejected the package: {}",
        result.package_msg
    );
    Ok(())
}
