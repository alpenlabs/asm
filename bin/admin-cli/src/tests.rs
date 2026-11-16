use std::fs;

use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness, absolute::LockTime, secp256k1::SecretKey, transaction::Version,
};
use bitcoind_async_client::traits::Reader;
use clap::{Parser, error::ErrorKind};
use serde_json::{Value, json};
use strata_asm_admin_threshold_sig::{IndexedSignature, SignatureSet};
use strata_asm_proto_admin_txs::{
    actions::{CancelAction, MultisigAction, UpdateAction, updates::AsmStfVkUpdate},
    signing_message::SigningMessage,
};
use strata_l1_txfmt::MagicBytes;
use strata_predicate::PredicateKey;
use strata_test_utils_btcio::{get_bitcoind_and_client, mine_blocks};

use super::*;

const MAGIC: MagicBytes = MagicBytes::new(*b"ALPN");

const TESTNET_PARAMS: &str = include_str!("../../../crates/params/envs/testnet.json");

fn keys() -> [SecretKey; 3] {
    [1u8, 2, 3].map(|b| SecretKey::from_slice(&[b; 32]).expect("valid key"))
}

fn address(key: &SecretKey, network: Network) -> String {
    P2wpkhAddress::from_pubkey(&PublicKey::from_secret_key(SECP256K1, key))
        .to_address(network)
        .to_string()
}

fn asm_stf_vk_action() -> MultisigAction {
    MultisigAction::Update(UpdateAction::AsmStfVk(AsmStfVkUpdate::new(
        PredicateKey::always_accept(),
    )))
}

/// Signs `action` with each `(index, key)` and formats the result as `--signature` values.
fn signatures(
    action: &MultisigAction,
    seq_no: u64,
    network: Network,
    signers: &[(u8, &SecretKey)],
) -> Vec<String> {
    let message = SigningMessage::for_action(action, seq_no, network);
    signers
        .iter()
        .map(|(index, key)| format!("{index}:{}", encode_signature(&message.sign(key))))
        .collect()
}

/// `--network --magic --signer.. --threshold` for a 2-of-3 set of [`keys`].
fn explicit_authority(network: Network) -> Vec<String> {
    let mut args = vec![
        "--network".to_owned(),
        network.to_string(),
        "--magic".to_owned(),
        "ALPN".to_owned(),
        "--threshold".to_owned(),
        "2".to_owned(),
    ];
    for key in &keys() {
        args.extend(["--signer".to_owned(), address(key, network)]);
    }
    args
}

/// Parses `verify` with `authority` and `signatures` for an ASM STF update at `seq_no` 4.
fn run_verify(authority: Vec<String>, signatures: Vec<String>) -> anyhow::Result<()> {
    let mut args = vec!["asm-admin".to_owned(), "verify".to_owned()];
    args.extend(authority);
    args.extend(["--seq-no".to_owned(), "4".to_owned()]);
    for signature in signatures {
        args.extend(["--signature".to_owned(), signature]);
    }
    args.extend(["asm-stf-vk", "--predicate", "AlwaysAccept"].map(str::to_owned));
    let Command::Verify(args) = Cli::try_parse_from(args)?.command else {
        panic!("parsed a verify command");
    };
    verify(args)
}

#[test]
fn cancel_names_the_queued_update() {
    let cli = Cli::try_parse_from([
        "asm-admin",
        "message",
        "--network",
        "signet",
        "--seq-no",
        "4",
        "cancel",
        "--id",
        "3",
        "asm-stf-vk",
        "--predicate",
        "AlwaysAccept",
    ])
    .unwrap();
    let Command::Message(args) = cli.command else {
        panic!("parsed a message command");
    };

    let action = args.action.into_action(Network::Signet).unwrap();

    let MultisigAction::Update(update) = asm_stf_vk_action() else {
        unreachable!()
    };
    assert_eq!(action, MultisigAction::Cancel(CancelAction::new(3, update)));
}

#[test]
fn safe_harbor_from_another_network_is_rejected() {
    let (key, _) = keys()[0].x_only_public_key(SECP256K1);
    let mainnet = Address::p2tr(SECP256K1, key, None, Network::Bitcoin).to_string();
    let cli = Cli::try_parse_from([
        "asm-admin",
        "message",
        "--network",
        "signet",
        "--seq-no",
        "1",
        "safe-harbor",
        "--address",
        &mainnet,
    ])
    .unwrap();
    let Command::Message(args) = cli.command else {
        panic!("parsed a message command");
    };

    assert!(args.action.into_action(Network::Signet).is_err());
}

#[test]
fn two_of_three_signatures_verify() {
    let [k0, _, k2] = keys();
    let sigs = signatures(
        &asm_stf_vk_action(),
        4,
        Network::Signet,
        &[(0, &k0), (2, &k2)],
    );

    run_verify(explicit_authority(Network::Signet), sigs).unwrap();
}

#[test]
fn one_of_three_is_below_threshold() {
    let [k0, ..] = keys();
    let sigs = signatures(&asm_stf_vk_action(), 4, Network::Signet, &[(0, &k0)]);

    let err = run_verify(explicit_authority(Network::Signet), sigs).unwrap_err();

    assert!(err.to_string().contains("insufficient"), "{err:#}");
}

#[test]
fn signature_under_the_wrong_index_names_the_signer() {
    let [k0, _, k2] = keys();
    let sigs = signatures(
        &asm_stf_vk_action(),
        4,
        Network::Signet,
        &[(1, &k0), (2, &k2)],
    );

    let err = run_verify(explicit_authority(Network::Signet), sigs).unwrap_err();

    assert!(err.to_string().starts_with("signature 1 "), "{err:#}");
}

#[test]
fn signatures_for_another_network_fail() {
    let [k0, _, k2] = keys();
    let sigs = signatures(
        &asm_stf_vk_action(),
        4,
        Network::Regtest,
        &[(0, &k0), (2, &k2)],
    );

    assert!(run_verify(explicit_authority(Network::Signet), sigs).is_err());
}

#[test]
fn signatures_for_another_seq_no_fail() {
    let [k0, _, k2] = keys();
    let sigs = signatures(
        &asm_stf_vk_action(),
        5,
        Network::Signet,
        &[(0, &k0), (2, &k2)],
    );

    assert!(run_verify(explicit_authority(Network::Signet), sigs).is_err());
}

#[test]
fn repeated_signer_index_is_rejected() {
    let [k0, ..] = keys();
    let sig = signatures(&asm_stf_vk_action(), 4, Network::Signet, &[(0, &k0)]);

    assert!(
        run_verify(
            explicit_authority(Network::Signet),
            [sig.clone(), sig].concat()
        )
        .is_err()
    );
}

/// Hardware wallets sign P2WPKH keys with BIP-137 headers 39-42 rather than 31-34.
#[test]
fn p2wpkh_signature_headers_verify() {
    let [k0, k1, _] = keys();
    let message = SigningMessage::for_action(&asm_stf_vk_action(), 4, Network::Signet);
    let sigs = [(0, &k0), (1, &k1)].map(|(index, key)| {
        let mut signature = message.sign(key);
        signature[0] += 8;
        format!("{index}:{}", encode_signature(&signature))
    });

    run_verify(explicit_authority(Network::Signet), sigs.to_vec()).unwrap();
}

#[test]
fn params_file_supplies_the_chain_and_signers() {
    let [k0, k1, k2] = keys();
    let mut params: Value = serde_json::from_str(TESTNET_PARAMS).unwrap();
    let admin = params["genesis"]["subprotocols"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|s| s.get_mut("Admin"))
        .unwrap();
    let signers = [&k0, &k1, &k2].map(|k| address(k, Network::Signet));
    admin["strata_administrator"] = json!({ "signers": signers, "threshold": 2 });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("params.json");
    fs::write(&path, params.to_string()).unwrap();
    let authority = vec!["--params".to_owned(), path.display().to_string()];

    let sigs = signatures(
        &asm_stf_vk_action(),
        4,
        Network::Signet,
        &[(0, &k0), (1, &k1)],
    );
    run_verify(authority, sigs).unwrap();
}

#[test]
fn params_file_excludes_explicit_signers() {
    let mut args = vec!["asm-admin", "verify", "--params", "params.json"];
    args.extend([
        "--network",
        "signet",
        "--seq-no",
        "1",
        "--signature",
        "0:AAAA",
    ]);
    args.extend(["asm-stf-vk", "--predicate", "AlwaysAccept"]);

    assert!(Cli::try_parse_from(args).is_err());
}

#[test]
fn zero_fee_rate_is_rejected() {
    let signature = format!("0:{}", encode_signature(&[0; 65]));
    let mut args = vec![
        "asm-admin",
        "submit",
        "--params",
        "params.json",
        "--seq-no",
        "1",
    ];
    args.extend([
        "--signature",
        &signature,
        "--btc-url",
        "http://127.0.0.1:8332",
    ]);
    args.extend([
        "--btc-user",
        "user",
        "--btc-password",
        "password",
        "--fee-rate",
        "0",
    ]);
    args.extend(["asm-stf-vk", "--predicate", "AlwaysAccept"]);

    let err = Cli::try_parse_from(args).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::ValueValidation);
}

fn signed_payload_for_tests(network: Network) -> SignedPayload {
    let [k0, _, k2] = keys();
    let action = asm_stf_vk_action();
    let message = SigningMessage::for_action(&action, 4, network);
    let signatures = [(0, &k0), (2, &k2)]
        .map(|(index, key)| IndexedSignature::new(index, message.sign(key)))
        .to_vec();
    SignedPayload::new(4, action, SignatureSet::new(signatures).unwrap())
}

fn commit_paying(address: &Address, value: Amount) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: address.script_pubkey(),
        }],
    }
}

#[test]
fn reveal_pays_the_fee_rate_and_returns_the_rest() {
    let envelope = Envelope::new(
        signed_payload_for_tests(Network::Signet),
        MAGIC,
        Network::Signet,
    )
    .unwrap();
    let (key, _) = keys()[0].x_only_public_key(SECP256K1);
    let change = Address::p2tr(SECP256K1, key, None, Network::Signet).script_pubkey();
    let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
    let value = envelope.commit_value(fee_rate, &change).unwrap();
    let commit = commit_paying(envelope.address(), value + Amount::from_sat(1_000));

    let reveal = envelope
        .build_reveal(&commit, change.clone(), fee_rate)
        .unwrap();

    let fee = value + Amount::from_sat(1_000) - reveal.output[1].value;
    assert_eq!(fee, fee_rate.fee_vb(reveal.vsize() as u64).unwrap());
    assert_eq!(reveal.output[1].script_pubkey, change);
}

#[test]
fn commit_below_the_reveal_cost_is_rejected() {
    let envelope = Envelope::new(
        signed_payload_for_tests(Network::Signet),
        MAGIC,
        Network::Signet,
    )
    .unwrap();
    let change = envelope.address().script_pubkey();
    let fee_rate = FeeRate::from_sat_per_vb(3).unwrap();
    let value = envelope.commit_value(fee_rate, &change).unwrap();
    let commit = commit_paying(envelope.address(), value - Amount::from_sat(1));

    assert!(envelope.build_reveal(&commit, change, fee_rate).is_err());
}

/// The transactions a regtest node accepts and mines carry the payload the ASM decodes.
#[tokio::test]
async fn regtest_node_mines_the_admin_transactions() {
    let (bitcoind, client) = get_bitcoind_and_client();
    mine_blocks(&bitcoind, &client, 101, None).await.unwrap();
    let envelope = Envelope::new(
        signed_payload_for_tests(Network::Regtest),
        MAGIC,
        Network::Regtest,
    )
    .unwrap();
    let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();

    let (commit, reveal) = wallet::build_transactions(&client, &envelope, fee_rate)
        .await
        .unwrap();
    wallet::check_package(&client, &commit, &reveal)
        .await
        .unwrap();
    wallet::broadcast(&client, &commit, &reveal).await.unwrap();
    let [block_hash] = mine_blocks(&bitcoind, &client, 1, None)
        .await
        .unwrap()
        .try_into()
        .unwrap();

    let block = client.get_block(&block_hash).await.unwrap();
    let txids: Vec<_> = block.txdata.iter().map(Transaction::compute_txid).collect();
    assert!(txids.contains(&commit.compute_txid()));
    assert!(txids.contains(&reveal.compute_txid()));
}
