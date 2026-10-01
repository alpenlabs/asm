//! Test-only CLI that lets the Python functional tests put ASM transactions on a regtest chain.
//!
//! It reuses the integration-test harness for signing and envelope building, so the functional
//! tests share one implementation of the admin wire format and signing message with the Rust
//! tests. Admin signatures and envelope addresses are regtest-only.
#![allow(
    unused_crate_dependencies,
    reason = "dependencies shared across integration tests"
)]

use std::collections::HashMap;

use bitcoin::secp256k1::SecretKey;
use clap::{Args, Parser, Subcommand};
use corepc_node::{client::client_sync::Auth, Client};
use integration_tests::harness::{
    admin::{asm_stf_vk_update, AdminContext},
    test_harness::build_envelope_tx,
};
use strata_l1_txfmt::MagicBytes;
use strata_predicate::PredicateKey;

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Signs an ASM STF predicate update and broadcasts it. Prints the reveal txid.
    SubmitAsmStfUpdate(SubmitAsmStfUpdateArgs),
}

#[derive(Debug, Args)]
struct SubmitAsmStfUpdateArgs {
    /// Bitcoind wallet RPC URL; the wallet funds the envelope.
    #[arg(long)]
    btc_url: String,
    #[arg(long)]
    btc_user: String,
    #[arg(long)]
    btc_password: String,
    /// SPS-50 magic bytes the ASM was launched with.
    #[arg(long)]
    magic: MagicBytes,
    /// Hex secret key of signer 0 of the role that authorizes the update.
    #[arg(long)]
    admin_sk: SecretKey,
    /// Must be above the role's last accepted sequence number.
    #[arg(long)]
    seqno: u64,
    /// Predicate to activate, e.g. `Bip340Schnorr:<hex>`.
    #[arg(long)]
    predicate: PredicateKey,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::SubmitAsmStfUpdate(args) => submit_asm_stf_update(args),
    }
}

fn submit_asm_stf_update(args: SubmitAsmStfUpdateArgs) -> anyhow::Result<()> {
    let rpc = Client::new_with_auth(
        &args.btc_url,
        Auth::UserPass(args.btc_user, args.btc_password),
    )?;
    let action = asm_stf_vk_update(args.predicate);
    let ctx = AdminContext::new(HashMap::from([(
        action.required_role(),
        (vec![args.admin_sk], vec![0]),
    )]));
    let payload = ctx.sign_with_seqno(&action, args.seqno);
    let tx = build_envelope_tx(&rpc, args.magic, action.tag(), payload, None)?;
    let txid = rpc.send_raw_transaction(&tx)?.txid()?;
    println!("{txid}");
    Ok(())
}
