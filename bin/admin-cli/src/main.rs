//! `asm-admin`: sign ASM admin actions and submit them to Bitcoin.
//!
//! Signers run `message` or `sign` offline and send their signature to a coordinator. The
//! coordinator runs `verify` to check the signatures against the role's signer set.

mod action;
mod authority;
mod signature;

#[cfg(test)]
mod tests;

use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

use anyhow::Context;
use bitcoin::{
    Network,
    secp256k1::{PublicKey, SECP256K1},
};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use strata_asm_admin_threshold_sig::{IndexedSignature, P2wpkhAddress};
use strata_asm_proto_admin_txs::{parser::SignedPayload, signing_message::SigningMessage};

use crate::{
    action::ActionCmd,
    authority::{AuthorityArgs, Chain, verify_signatures},
    signature::{encode_signature, parse_indexed_signature, parse_secret_key},
};

/// Environment variable `sign` reads the signer's key from.
const KEY_ENV: &str = "STRATA_ADMIN_KEY";

#[derive(Debug, Parser)]
#[command(about = "Sign ASM admin actions and submit them to Bitcoin")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the exact text a signer signs, for a wallet's `signmessage`.
    ///
    /// The text goes to stdout with no trailing newline.
    Message(UnsignedArgs),
    /// Sign an action with the key in `STRATA_ADMIN_KEY` (an xpriv or 32 hex bytes).
    ///
    /// Prints the signing message and the signer's address on stderr, and the base64
    /// signature on stdout.
    Sign(UnsignedArgs),
    /// Check collected signatures against the role's signer set.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
#[command(subcommand_value_name = "ACTION", subcommand_help_heading = "Actions")]
struct UnsignedArgs {
    /// Bitcoin network the chain is anchored to.
    #[arg(long)]
    network: Network,

    /// Sequence number of the action. Must be above the role's last accepted one.
    #[arg(long)]
    seq_no: u64,

    #[command(subcommand)]
    action: ActionCmd,
}

/// What every command that handles collected signatures needs.
#[derive(Debug, Args)]
struct SignedArgs {
    #[command(flatten)]
    authority: AuthorityArgs,

    /// Sequence number the signers signed.
    #[arg(long)]
    seq_no: u64,

    /// Signature as `<signer index>:<base64>`. Repeat for each signer.
    #[arg(long = "signature", required = true, value_parser = parse_indexed_signature)]
    signatures: Vec<IndexedSignature>,
}

#[derive(Debug, Args)]
#[command(subcommand_value_name = "ACTION", subcommand_help_heading = "Actions")]
struct VerifyArgs {
    #[command(flatten)]
    signed: SignedArgs,

    #[command(subcommand)]
    action: ActionCmd,
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Message(args) => message(args),
        Command::Sign(args) => sign(args),
        Command::Verify(args) => verify(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn message(args: UnsignedArgs) -> anyhow::Result<()> {
    let action = args.action.into_action(args.network)?;
    let message = SigningMessage::for_action(&action, args.seq_no, args.network);
    let mut stdout = io::stdout();
    write!(stdout, "{}", message.as_str())?;
    stdout.flush()?;
    // Ends the line on a terminal without changing what stdout carries.
    eprintln!();
    Ok(())
}

fn sign(args: UnsignedArgs) -> anyhow::Result<()> {
    let key = env::var(KEY_ENV).with_context(|| format!("set {KEY_ENV} to the signer's key"))?;
    let key = parse_secret_key(&key).with_context(|| format!("invalid {KEY_ENV}"))?;
    let action = args.action.into_action(args.network)?;
    let message = SigningMessage::for_action(&action, args.seq_no, args.network);
    let signer = P2wpkhAddress::from_pubkey(&PublicKey::from_secret_key(SECP256K1, &key));

    eprintln!("{}\n", message.as_str());
    eprintln!("Signed by {}", signer.to_address(args.network));
    println!("{}", encode_signature(&message.sign(&key)));
    Ok(())
}

/// Builds the action and checks the signatures over it, as the chain will.
fn signed_payload(signed: SignedArgs, action: ActionCmd) -> anyhow::Result<(SignedPayload, Chain)> {
    let chain = signed.authority.load()?;
    let action = action.into_action(chain.network)?;
    let message = SigningMessage::for_action(&action, signed.seq_no, chain.network);
    let signatures = verify_signatures(
        &chain.signers(action.required_role()),
        chain.network,
        &signed.signatures,
        &message.compute_sighash().0,
    )?;
    Ok((SignedPayload::new(signed.seq_no, action, signatures), chain))
}

fn verify(args: VerifyArgs) -> anyhow::Result<()> {
    let (payload, chain) = signed_payload(args.signed, args.action)?;
    let role = payload.action.required_role();
    let report = json!({
        "role": role.to_string(),
        "network": chain.network.to_string(),
        "magic": chain.magic.to_string(),
        "seq_no": payload.seqno,
        "signers": payload.signatures.indices().collect::<Vec<_>>(),
        "threshold": chain.signers(role).threshold(),
    });
    println!("{report:#}");
    Ok(())
}
