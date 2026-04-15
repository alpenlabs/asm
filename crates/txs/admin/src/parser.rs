use strata_asm_common::TxInputRef;
use strata_l1_envelope_fmt::parser::parse_envelope_payload;

use crate::{
    constants::AdminTxType, errors::AdministrationTxParseError, signed_action::SignedAction,
};

/// Parses a transaction into a normalized signed administration action.
///
/// The parser first validates the SPS-50 tx type from the OP_RETURN tag, then decodes the
/// tx-type-specific envelope payload into the existing admin action model.
pub fn parse_tx(tx: &TxInputRef<'_>) -> Result<SignedAction, AdministrationTxParseError> {
    let raw_tx_type = tx.tag().tx_type();
    let tx_type = AdminTxType::try_from(raw_tx_type)
        .map_err(|raw_tx_type| AdministrationTxParseError::UnknownTxType { raw_tx_type })?;

    let bitcoin_tx = tx.tx();
    if bitcoin_tx.input.is_empty() {
        return Err(AdministrationTxParseError::MissingInput { tx_type, index: 0 });
    }

    let payload_script = bitcoin_tx.input[0]
        .witness
        .taproot_leaf_script()
        .ok_or(AdministrationTxParseError::MissingLeafScript { tx_type })?
        .script
        .into();

    let envelope_payload = parse_envelope_payload(&payload_script)
        .map_err(|source| AdministrationTxParseError::MalformedEnvelope { tx_type, source })?;

    SignedAction::from_payload_bytes(tx_type, &envelope_payload)
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime,
        blockdata::script::Builder as ScriptBuilder,
        key::{UntweakedKeypair, XOnlyPublicKey},
        secp256k1::{PublicKey, SECP256K1, Secp256k1, SecretKey, schnorr::Signature},
        taproot::{LeafVersion, TaprootBuilder},
        transaction::Version,
    };
    use rand::{RngCore, rngs::OsRng};
    use ssz::Encode;
    use ssz_derive::Encode as DeriveEncode;
    use strata_asm_common::TxInputRef;
    use strata_asm_params::Role;
    use strata_asm_txs_test_utils::TEST_MAGIC_BYTES;
    use strata_crypto::{
        keys::compressed::CompressedPublicKey,
        threshold_signature::{SignatureSet, ThresholdConfigUpdate},
    };
    use strata_identifiers::Buf32;
    use strata_l1_envelope_fmt::builder::build_envelope_script;
    use strata_l1_txfmt::{ParseConfig, TagData};
    use strata_predicate::PredicateKey;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::parse_tx;
    use crate::{
        actions::{
            CancelAction, MultisigAction, Sighash, UpdateAction,
            updates::{
                multisig::MultisigUpdate,
                operator::OperatorSetUpdate,
                predicate::{PredicateUpdate, ProofType},
                seq::SequencerUpdate,
            },
        },
        constants::{ADMINISTRATION_SUBPROTOCOL_ID, AdminTxType},
        errors::AdministrationTxParseError,
        signed_action::SignedAction,
        test_utils::create_signature_set,
    };

    fn parse_admin_tx(tx: &Transaction) -> Result<SignedAction, AdministrationTxParseError> {
        let tag_data_ref = ParseConfig::new(TEST_MAGIC_BYTES)
            .try_parse_tx(tx)
            .expect("test transaction should parse as SPS-50");
        parse_tx(&TxInputRef::new(tx, tag_data_ref))
    }

    fn build_test_tx(raw_tx_type: u8, payload: Vec<u8>) -> Transaction {
        let tag = TagData::new(ADMINISTRATION_SUBPROTOCOL_ID, raw_tx_type, vec![])
            .expect("empty admin aux data always fits");
        let sps50_script = ParseConfig::new(TEST_MAGIC_BYTES)
            .encode_script_buf(&tag.as_ref())
            .unwrap();

        let mut rand_bytes = [0; 32];
        RngCore::fill_bytes(&mut OsRng, &mut rand_bytes);
        let key_pair = UntweakedKeypair::from_seckey_slice(SECP256K1, &rand_bytes).unwrap();
        let public_key = XOnlyPublicKey::from_keypair(&key_pair).0;

        let envelope = build_envelope_script(&payload).expect("simple envelope build should work");
        let reveal_script = ScriptBuilder::from(envelope.into_bytes())
            .push_int(1)
            .into_script();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .unwrap()
            .finalize(SECP256K1, public_key)
            .expect("could not build taproot spend info");

        let signature = Signature::from_slice(&[0u8; 64]).unwrap();
        let mut witness = Witness::new();
        witness.push(signature.as_ref());
        witness.push(reveal_script.clone());
        witness.push(
            taproot_spend_info
                .control_block(&(reveal_script, LeafVersion::TapScript))
                .expect("could not create control block")
                .serialize(),
        );

        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: sps50_script,
            }],
        }
    }

    fn build_test_tx_with_reveal_script(raw_tx_type: u8, reveal_script: ScriptBuf) -> Transaction {
        let tag = TagData::new(ADMINISTRATION_SUBPROTOCOL_ID, raw_tx_type, vec![])
            .expect("empty admin aux data always fits");
        let sps50_script = ParseConfig::new(TEST_MAGIC_BYTES)
            .encode_script_buf(&tag.as_ref())
            .unwrap();

        let mut rand_bytes = [0; 32];
        RngCore::fill_bytes(&mut OsRng, &mut rand_bytes);
        let key_pair = UntweakedKeypair::from_seckey_slice(SECP256K1, &rand_bytes).unwrap();
        let public_key = XOnlyPublicKey::from_keypair(&key_pair).0;

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .unwrap()
            .finalize(SECP256K1, public_key)
            .expect("could not build taproot spend info");

        let signature = Signature::from_slice(&[0u8; 64]).unwrap();
        let mut witness = Witness::new();
        witness.push(signature.as_ref());
        witness.push(reveal_script.clone());
        witness.push(
            taproot_spend_info
                .control_block(&(reveal_script, LeafVersion::TapScript))
                .expect("could not create control block")
                .serialize(),
        );

        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: sps50_script,
            }],
        }
    }

    fn create_test_signature_set() -> SignatureSet {
        let privkey = SecretKey::new(&mut rand::thread_rng());
        let action = MultisigAction::Cancel(CancelAction::new(7));
        let sighash = action.compute_sighash(1);
        create_signature_set(&[privkey], &[0], sighash)
    }

    fn create_signed_action(action: MultisigAction, seqno: u64) -> SignedAction {
        let sighash = action.compute_sighash(seqno);
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let signatures = create_signature_set(&[secret_key], &[0], sighash);
        SignedAction::new(seqno, action, signatures)
    }

    fn assert_roundtrip(tx_type: AdminTxType, signed_action: SignedAction) {
        let tx = build_test_tx(tx_type.into(), signed_action.payload_bytes());
        let parsed = parse_admin_tx(&tx).unwrap();
        assert_eq!(parsed, signed_action);
    }

    fn assert_wire_len(signed_action: SignedAction, expected_len: usize) {
        assert_eq!(signed_action.payload_bytes().len(), expected_len);
    }

    #[test]
    fn test_roundtrip_cancel_payload() {
        let signed_action = create_signed_action(MultisigAction::Cancel(CancelAction::new(42)), 9);
        assert_roundtrip(AdminTxType::Cancel, signed_action);
    }

    #[test]
    fn test_roundtrip_admin_multisig_payload() {
        let mut arb = ArbitraryGenerator::new();
        let update = MultisigUpdate::new(arb.generate(), Role::StrataAdministrator);
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::Multisig(update)), 3);
        assert_roundtrip(AdminTxType::StrataAdminMultisigUpdate, signed_action);
    }

    #[test]
    fn test_roundtrip_seq_manager_multisig_payload() {
        let mut arb = ArbitraryGenerator::new();
        let update = MultisigUpdate::new(arb.generate(), Role::StrataSequencerManager);
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::Multisig(update)), 4);
        assert_roundtrip(AdminTxType::StrataSeqManagerMultisigUpdate, signed_action);
    }

    #[test]
    fn test_roundtrip_operator_payload() {
        let mut arb = ArbitraryGenerator::new();
        let update = OperatorSetUpdate::new(arb.generate(), arb.generate());
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::OperatorSet(update)), 5);
        assert_roundtrip(AdminTxType::OperatorUpdate, signed_action);
    }

    #[test]
    fn test_roundtrip_sequencer_payload() {
        let mut arb = ArbitraryGenerator::new();
        let update = SequencerUpdate::new(arb.generate());
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::Sequencer(update)), 6);
        assert_roundtrip(AdminTxType::SequencerUpdate, signed_action);
    }

    #[test]
    fn test_roundtrip_ol_stf_predicate_payload() {
        let update = PredicateUpdate::new(PredicateKey::always_accept(), ProofType::OLStf);
        let signed_action = create_signed_action(
            MultisigAction::Update(UpdateAction::VerifyingKey(update)),
            7,
        );
        assert_roundtrip(AdminTxType::OlStfVkUpdate, signed_action);
    }

    #[test]
    fn test_roundtrip_asm_predicate_payload() {
        let update = PredicateUpdate::new(PredicateKey::always_accept(), ProofType::Asm);
        let signed_action = create_signed_action(
            MultisigAction::Update(UpdateAction::VerifyingKey(update)),
            8,
        );
        assert_roundtrip(AdminTxType::AsmStfVkUpdate, signed_action);
    }

    #[test]
    fn test_unknown_tx_type_rejected_before_decode() {
        let tx = build_test_tx(
            99,
            create_signed_action(MultisigAction::Cancel(CancelAction::new(1)), 1).payload_bytes(),
        );
        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::UnknownTxType { raw_tx_type: 99 }
        ));
    }

    #[test]
    fn test_mismatched_tag_and_payload_rejected() {
        let signed_action = create_signed_action(MultisigAction::Cancel(CancelAction::new(3)), 1);
        let tx = build_test_tx(
            AdminTxType::StrataAdminMultisigUpdate.into(),
            signed_action.payload_bytes(),
        );

        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::MalformedPayload {
                tx_type: AdminTxType::StrataAdminMultisigUpdate,
                ..
            }
        ));
    }

    #[test]
    fn test_truncated_payload_rejected() {
        let signed_action = create_signed_action(
            MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(Buf32::from(
                [1u8; 32],
            )))),
            1,
        );
        let mut bytes = signed_action.payload_bytes();
        bytes.pop();
        let tx = build_test_tx(AdminTxType::SequencerUpdate.into(), bytes);

        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::MalformedPayload {
                tx_type: AdminTxType::SequencerUpdate,
                ..
            }
        ));
    }

    #[test]
    fn test_missing_input_rejected() {
        let raw_tx_type: u8 = AdminTxType::Cancel.into();
        let tag = TagData::new(ADMINISTRATION_SUBPROTOCOL_ID, raw_tx_type, vec![])
            .expect("empty admin aux data always fits");
        let sps50_script = ParseConfig::new(TEST_MAGIC_BYTES)
            .encode_script_buf(&tag.as_ref())
            .unwrap();

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: sps50_script,
            }],
        };

        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::MissingInput {
                tx_type: AdminTxType::Cancel,
                index: 0,
            }
        ));
    }

    #[test]
    fn test_missing_leaf_script_rejected() {
        let mut tx = build_test_tx(
            AdminTxType::Cancel.into(),
            create_signed_action(MultisigAction::Cancel(CancelAction::new(1)), 1).payload_bytes(),
        );
        tx.input[0].witness = Witness::new();

        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::MissingLeafScript {
                tx_type: AdminTxType::Cancel
            }
        ));
    }

    #[test]
    fn test_malformed_envelope_rejected() {
        let reveal_script = ScriptBuilder::new().push_int(1).into_script();
        let tx = build_test_tx_with_reveal_script(AdminTxType::Cancel.into(), reveal_script);

        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::MalformedEnvelope {
                tx_type: AdminTxType::Cancel,
                ..
            }
        ));
    }

    #[test]
    fn test_zero_threshold_rejected() {
        #[derive(DeriveEncode)]
        struct InvalidMultisigPayload {
            seqno: u64,
            add_members: Vec<CompressedPublicKey>,
            remove_members: Vec<CompressedPublicKey>,
            new_threshold: u8,
            signatures: SignatureSet,
        }

        let secp = Secp256k1::new();
        let privkey = SecretKey::new(&mut rand::thread_rng());
        let pubkey = CompressedPublicKey::from(PublicKey::from_secret_key(&secp, &privkey));
        let payload = InvalidMultisigPayload {
            seqno: 1,
            add_members: vec![pubkey],
            remove_members: vec![],
            new_threshold: 0,
            signatures: create_test_signature_set(),
        };
        let tx = build_test_tx(
            AdminTxType::StrataAdminMultisigUpdate.into(),
            payload.as_ssz_bytes(),
        );

        let err = parse_admin_tx(&tx).unwrap_err();
        assert!(matches!(
            err,
            AdministrationTxParseError::InvalidThreshold {
                tx_type: AdminTxType::StrataAdminMultisigUpdate
            }
        ));
    }

    #[test]
    fn test_cancel_wire_len_regression() {
        let signed_action = create_signed_action(MultisigAction::Cancel(CancelAction::new(42)), 1);
        assert_wire_len(signed_action, 86);
    }

    #[test]
    fn test_multisig_wire_len_regression() {
        let secp = Secp256k1::new();
        let member = CompressedPublicKey::from(PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[1u8; 32]).unwrap(),
        ));
        let update = MultisigUpdate::new(
            ThresholdConfigUpdate::new(vec![member], vec![], NonZero::new(1).unwrap()),
            Role::StrataAdministrator,
        );
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::Multisig(update)), 1);
        assert_wire_len(signed_action, 124);
    }

    #[test]
    fn test_operator_wire_len_regression() {
        let update = OperatorSetUpdate::new(vec![Buf32::from([1u8; 32])], vec![]);
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::OperatorSet(update)), 1);
        assert_wire_len(signed_action, 122);
    }

    #[test]
    fn test_sequencer_wire_len_regression() {
        let update = SequencerUpdate::new(Buf32::from([2u8; 32]));
        let signed_action =
            create_signed_action(MultisigAction::Update(UpdateAction::Sequencer(update)), 1);
        assert_wire_len(signed_action, 114);
    }

    #[test]
    fn test_predicate_wire_len_regression() {
        let update = PredicateUpdate::new(PredicateKey::always_accept(), ProofType::OLStf);
        let signed_action = create_signed_action(
            MultisigAction::Update(UpdateAction::VerifyingKey(update)),
            1,
        );
        assert_wire_len(signed_action, 91);
    }
}
