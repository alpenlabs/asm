//! Test-support CLI for crafting and submitting ASM protocol transactions.
//!
//! The functional-test suite is Python, but everything needed to build a
//! multisig-signed admin action or a musig2-signed unstake lives in this
//! workspace's Rust crates. This binary bridges the gap: the Python tests
//! shell out to it against their regtest `bitcoind` (wallet enabled) and mine
//! the result themselves.
//!
//! Nothing here mines or waits — every subcommand leaves its transactions in
//! the mempool and prints the txid(s) that matter.

use std::slice;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
    absolute::LockTime,
    hashes::{Hash as _, sha256},
    key::UntweakedKeypair,
    script,
    secp256k1::{SECP256K1, SecretKey, XOnlyPublicKey},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
};
use bitcoind_async_client::{
    Auth, Client,
    traits::{Broadcaster, Signer, Wallet},
    types::CreateRawTransactionOutput,
};
use clap::{Args, Parser, Subcommand};
use k256::schnorr::SigningKey;
use rand::RngCore;
use strata_asm_proto_admin_txs::{
    actions::{MultisigAction, UpdateAction, updates::AsmStfVkUpdate},
    parser::SignedPayload,
    test_utils::create_signature_set,
};
use strata_asm_proto_bridge_v1_txs::unstake::{UnstakeTxHeaderAux, stake_connector_script};
use strata_crypto::{EvenSecretKey, keys::constants::UNSPENDABLE_PUBLIC_KEY};
use strata_l1_envelope_fmt::builder::build_envelope_script;
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_predicate::{PredicateKey, PredicateTypeId};
use strata_test_utils_btcio::{
    address::derive_musig2_p2tr_address, signing::sign_musig2_scriptpath,
};

/// Fee attached to crafted transactions; regtest only cares that it is > 0.
const FEE: Amount = Amount::from_sat(1000);

/// Amount funded into intermediate outputs (commit / stake connector).
const FUNDING_AMOUNT: Amount = Amount::from_sat(10_000);

#[derive(Debug, Parser)]
#[command(about = "Craft and submit ASM protocol transactions against regtest")]
struct Cli {
    #[command(flatten)]
    rpc: RpcArgs,

    /// SPS-50 magic bytes tagging protocol transactions (4 ASCII chars).
    #[arg(long, default_value = "ALPN")]
    magic: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct RpcArgs {
    /// Bitcoin Core RPC URL (wallet enabled).
    #[arg(long, default_value = "http://localhost:18443")]
    rpc_url: String,

    /// RPC username.
    #[arg(long, default_value = "user")]
    rpc_user: String,

    /// RPC password.
    #[arg(long, default_value = "password")]
    rpc_password: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the `Bip340Schnorr` predicate string a native proving host with
    /// this signing key resolves to.
    DerivePredicate {
        /// 32-byte schnorr signing key, hex.
        #[arg(long)]
        schnorr_key: String,
    },

    /// Print the compressed secp256k1 public key of a secret key. Used to
    /// build params files whose multisig/operator configs must match keys the
    /// tests sign with.
    DerivePubkey {
        /// 32-byte secret key, hex.
        #[arg(long)]
        secret_key: String,
    },

    /// Build, sign and submit an ASM STF VK update admin action
    /// (commit + reveal, left in the mempool).
    SubmitVkUpdate {
        /// The new predicate, e.g. `Bip340Schnorr:<hex>` or `Sp1Groth16:<hex>`.
        #[arg(long)]
        new_predicate: String,

        /// Raw id of the fork the new artifact implements; rendered into the
        /// signing message and carried in the action.
        #[arg(long)]
        fork_id: u16,

        /// Strata administrator signing keys (32-byte hex), one per signer.
        #[arg(long, required = true)]
        signer_key: Vec<String>,

        /// Multisig sequence number for replay protection.
        #[arg(long, default_value_t = 1)]
        seqno: u64,
    },

    /// Fund a canonical stake connector for the operator set's N/N key and
    /// submit an unstake spending it (both left in the mempool).
    SubmitUnstake {
        /// Index of the operator to unstake.
        #[arg(long)]
        operator_idx: u32,

        /// Operator signing keys (32-byte hex), the full N/N set in order.
        #[arg(long, required = true)]
        operator_key: Vec<String>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::DerivePredicate { schnorr_key } => {
            let predicate = derive_native_predicate(&schnorr_key)?;
            // Print the same human-readable form serde uses (sans JSON quotes).
            let json = serde_json::to_value(&predicate)?;
            let rendered = json
                .as_str()
                .ok_or_else(|| anyhow!("predicate did not serialize to a string"))?
                .to_owned();
            println!("{rendered}");
            Ok(())
        }
        Command::DerivePubkey { secret_key } => {
            let bytes = hex::decode(&secret_key).context("secret key must be hex")?;
            let sk = SecretKey::from_slice(&bytes).context("invalid secp256k1 secret key")?;
            println!("{}", hex::encode(sk.public_key(SECP256K1).serialize()));
            Ok(())
        }
        Command::SubmitVkUpdate {
            new_predicate,
            fork_id,
            signer_key,
            seqno,
        } => {
            let client = connect(&cli.rpc)?;
            let magic = parse_magic(&cli.magic)?;
            let txid =
                submit_vk_update(&client, magic, &new_predicate, fork_id, &signer_key, seqno)
                    .await?;
            println!("{txid}");
            Ok(())
        }
        Command::SubmitUnstake {
            operator_idx,
            operator_key,
        } => {
            let client = connect(&cli.rpc)?;
            let magic = parse_magic(&cli.magic)?;
            let txid = submit_unstake(&client, magic, operator_idx, &operator_key).await?;
            println!("{txid}");
            Ok(())
        }
    }
}

fn connect(rpc: &RpcArgs) -> Result<Client> {
    Client::new(
        rpc.rpc_url.clone(),
        Auth::UserPass(rpc.rpc_user.clone(), rpc.rpc_password.clone()),
        None,
        None,
        None,
    )
    .context("failed to construct bitcoind RPC client")
}

fn parse_magic(magic: &str) -> Result<MagicBytes> {
    let bytes: [u8; 4] = magic
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow!("magic must be exactly 4 bytes, got {magic:?}"))?;
    Ok(MagicBytes::new(bytes))
}

/// Mirrors the prover's `resolve_native_predicate`: the predicate of a native
/// host is its BIP-340 verifying key, verbatim.
fn derive_native_predicate(schnorr_key_hex: &str) -> Result<PredicateKey> {
    let bytes = hex::decode(schnorr_key_hex).context("schnorr key must be hex")?;
    let signing_key = SigningKey::from_bytes(&bytes).context("invalid schnorr signing key")?;
    Ok(PredicateKey::new(
        PredicateTypeId::Bip340Schnorr,
        signing_key.verifying_key().to_bytes().to_vec(),
    ))
}

/// Parses a predicate from its human-readable string form
/// (`<TypeName>:<hex>`), the same encoding its serde impl uses.
fn parse_predicate(s: &str) -> Result<PredicateKey> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .with_context(|| format!("invalid predicate string {s:?}"))
}

fn parse_secret_keys(keys_hex: &[String]) -> Result<Vec<SecretKey>> {
    keys_hex
        .iter()
        .map(|k| {
            let bytes = hex::decode(k).context("signer key must be hex")?;
            SecretKey::from_slice(&bytes).context("invalid secp256k1 secret key")
        })
        .collect()
}

async fn submit_vk_update(
    client: &Client,
    magic: MagicBytes,
    new_predicate: &str,
    fork_id: u16,
    signer_keys_hex: &[String],
    seqno: u64,
) -> Result<Txid> {
    let predicate = parse_predicate(new_predicate)?;
    let privkeys = parse_secret_keys(signer_keys_hex)?;
    let signer_indices: Vec<u8> = (0..privkeys.len() as u8).collect();

    let action = MultisigAction::Update(UpdateAction::AsmStfVk(AsmStfVkUpdate::new(
        predicate, fork_id,
    )));
    let signature_set = create_signature_set(&privkeys, &signer_indices, &action, seqno);
    let payload = SignedPayload::new(seqno, action.clone(), signature_set);
    let payload_bytes = ssz::Encode::as_ssz_bytes(&payload);

    submit_envelope_tx(client, magic, &action.tag(), payload_bytes).await
}

/// Builds and submits an SPS-50 commit + reveal pair carrying `payload` in a
/// simple (no SPS-51 auth) envelope, mirroring the integration harness's
/// `build_envelope_tx`. Returns the reveal txid.
async fn submit_envelope_tx(
    client: &Client,
    magic: MagicBytes,
    sps50_tag: &strata_l1_txfmt::TagData,
    payload: Vec<u8>,
) -> Result<Txid> {
    let funding_amount = FUNDING_AMOUNT;

    // Random internal key; the reveal spends via the script path.
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let keypair = UntweakedKeypair::from_seckey_slice(SECP256K1, &key_bytes)?;
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);

    // `OP_FALSE OP_IF <payload> OP_ENDIF OP_TRUE` tapscript.
    let envelope = build_envelope_script(&payload).context("failed to build envelope script")?;
    let reveal_script = script::Builder::from(envelope.into_bytes())
        .push_int(1)
        .into_script();

    let spend_info = taproot_spend_info(internal_key, reveal_script.clone())?;
    let commit_address = Address::p2tr(
        SECP256K1,
        internal_key,
        spend_info.merkle_root(),
        Network::Regtest,
    );

    // Commit: wallet funds the taproot output.
    let (commit_txid, commit_vout) = fund_address(client, &commit_address, funding_amount).await?;

    // Reveal: OP_RETURN tag + change, spending the commit output.
    let op_return_script = ParseConfig::new(magic).encode_script_buf(&sps50_tag.as_ref())?;
    let change_address = client.get_new_address().await?;

    let mut reveal_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_txid, commit_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            },
            TxOut {
                value: funding_amount - FEE,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    };

    let control_block = spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow!("control block must exist for the envelope leaf"))?;
    let mut witness = Witness::new();
    witness.push(reveal_script.as_bytes());
    witness.push(control_block.serialize());
    reveal_tx.input[0].witness = witness;

    client
        .send_raw_transaction(&reveal_tx, None)
        .await
        .context("failed to broadcast reveal tx")
}

async fn submit_unstake(
    client: &Client,
    magic: MagicBytes,
    operator_idx: u32,
    operator_keys_hex: &[String],
) -> Result<Txid> {
    let operator_keys: Vec<EvenSecretKey> = parse_secret_keys(operator_keys_hex)?
        .into_iter()
        .map(EvenSecretKey::from)
        .collect();

    // Canonical stake connector committing to (stake_hash, N/N key):
    // P2TR(NUMS, single stake-connector leaf).
    let (_, nn_pubkey) = derive_musig2_p2tr_address(&operator_keys)
        .map_err(|e| anyhow!("operator keys must aggregate: {e:?}"))?;
    let mut preimage = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut preimage);
    let stake_hash = sha256::Hash::hash(&preimage).to_byte_array();
    let leaf_script = stake_connector_script(stake_hash, nn_pubkey);
    let spend_info = taproot_spend_info(*UNSPENDABLE_PUBLIC_KEY, leaf_script.clone())?;
    let stake_connector_address = Address::p2tr(
        SECP256K1,
        *UNSPENDABLE_PUBLIC_KEY,
        spend_info.merkle_root(),
        Network::Regtest,
    );

    // Fund the stake connector; the unstake chains onto it in the mempool.
    let (funding_txid, funding_vout) =
        fund_address(client, &stake_connector_address, FUNDING_AMOUNT).await?;

    // Unstake: OP_RETURN naming the operator + change.
    let aux = UnstakeTxHeaderAux::new(operator_idx);
    let tag_data = aux.build_tag_data();
    let op_return_script = ParseConfig::new(magic).encode_script_buf(&tag_data.as_ref())?;
    let change_address = client.get_new_address().await?;

    let prevout = TxOut {
        value: FUNDING_AMOUNT,
        script_pubkey: stake_connector_address.script_pubkey(),
    };
    let mut unstake_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding_txid, funding_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            },
            TxOut {
                value: FUNDING_AMOUNT - FEE,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    };

    // MuSig2 script-path signature by the full operator set, witness in the
    // [preimage, sig, script, control_block] layout ASM parses.
    let nn_sig = sign_musig2_scriptpath(
        &unstake_tx,
        &operator_keys,
        slice::from_ref(&prevout),
        0,
        &leaf_script,
        LeafVersion::TapScript,
    )
    .map_err(|e| anyhow!("musig2 script-path signing failed: {e:?}"))?;
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| anyhow!("control block must exist for the stake-connector leaf"))?;

    let mut witness = Witness::new();
    witness.push(preimage);
    witness.push(nn_sig.serialize());
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());
    unstake_tx.input[0].witness = witness;

    client
        .send_raw_transaction(&unstake_tx, None)
        .await
        .context("failed to broadcast unstake tx")
}

fn taproot_spend_info(
    internal_key: XOnlyPublicKey,
    leaf_script: ScriptBuf,
) -> Result<TaprootSpendInfo> {
    TaprootBuilder::new()
        .add_leaf(0, leaf_script)?
        .finalize(SECP256K1, internal_key)
        .map_err(|_| anyhow!("failed to finalize taproot spend info"))
}

/// Funds `address` with `amount` from the node wallet via the PSBT flow
/// (create-funded → wallet-sign → broadcast). Returns the created outpoint.
async fn fund_address(client: &Client, address: &Address, amount: Amount) -> Result<(Txid, u32)> {
    let outputs = [CreateRawTransactionOutput::AddressAmount {
        address: address.to_string(),
        amount: amount.to_btc(),
    }];
    let created = client
        .wallet_create_funded_psbt(&[], &outputs, None, None, None)
        .await
        .context("walletcreatefundedpsbt failed")?;
    let processed = client
        .wallet_process_psbt(&created.psbt.to_string(), Some(true), None, None)
        .await
        .context("walletprocesspsbt failed")?;
    ensure!(processed.complete, "wallet could not fully sign funding tx");

    let tx = processed
        .psbt
        .extract_tx()
        .context("failed to extract funding tx from PSBT")?;
    let vout = tx
        .output
        .iter()
        .position(|o| o.script_pubkey == address.script_pubkey())
        .ok_or_else(|| anyhow!("funded output not found in funding tx"))? as u32;

    let txid = client
        .send_raw_transaction(&tx, None)
        .await
        .context("failed to broadcast funding tx")?;
    Ok((txid, vout))
}
