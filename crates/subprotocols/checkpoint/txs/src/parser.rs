use strata_asm_checkpoint_types::CheckpointPayload;
use strata_asm_common::TxInputRef;
use strata_codec::decode_buf_exact;
use strata_codec_utils::CodecSsz;
use strata_l1_envelope_fmt::{SignedEnvelopeSpend, parse_signed_envelope_spend};

use crate::errors::{CheckpointTxError, CheckpointTxResult};

/// Parses the checkpoint envelope revealed by the first input of an SPS-50-tagged transaction.
///
/// Checks the format only: the input must be a taproot script-path spend of a tapscript leaf that
/// is a strict SPS-51 signed envelope leaf. Neither the envelope pubkey nor the payload is
/// authenticated: per SPS-51 the pubkey stands in for a signature only once the spent output is
/// shown to be a native P2TR output (see [`SignedEnvelopeSpend`]), and recognizing the pubkey is
/// the checkpoint subprotocol's policy.
///
/// # Errors
///
/// [`CheckpointTxError::MissingInputs`] if the transaction has no inputs, or
/// [`CheckpointTxError::EnvelopeSpend`] if the first input is not a signed envelope spend.
pub fn parse_checkpoint_envelope(tx: &TxInputRef<'_>) -> CheckpointTxResult<SignedEnvelopeSpend> {
    let envelope_input = tx
        .tx()
        .input
        .first()
        .ok_or(CheckpointTxError::MissingInputs)?;

    Ok(parse_signed_envelope_spend(envelope_input)?)
}

/// Decodes a checkpoint payload from the bytes an envelope carries.
///
/// # Errors
///
/// [`CheckpointTxError::CodecDecode`] if the bytes are not exactly one
/// `CodecSsz<CheckpointPayload>`.
pub fn decode_checkpoint_payload(bytes: &[u8]) -> CheckpointTxResult<CheckpointPayload> {
    let checkpoint: CodecSsz<CheckpointPayload> =
        decode_buf_exact(bytes).map_err(CheckpointTxError::CodecDecode)?;
    Ok(checkpoint.into_inner())
}

/// Extracts the checkpoint payload from an SPS-50-tagged transaction without authenticating it.
///
/// For reading back a transaction whose checkpoint has already been accepted. Anyone can post a
/// transaction this function accepts, so it must not decide whether a checkpoint is the
/// sequencer's.
///
/// # Errors
///
/// [`CheckpointTxError`] if the transaction does not carry a checkpoint envelope that
/// [`parse_checkpoint_envelope`] accepts and [`decode_checkpoint_payload`] decodes.
pub fn extract_checkpoint_from_envelope(
    tx: &TxInputRef<'_>,
) -> CheckpointTxResult<CheckpointPayload> {
    let spend = parse_checkpoint_envelope(tx)?;
    decode_checkpoint_payload(spend.unverified_leaf().payload())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Transaction, Witness, XOnlyPublicKey,
        key::Keypair,
        opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_NOT, OP_PUSHBYTES_0, OP_PUSHBYTES_32},
        secp256k1::SECP256K1,
        taproot::LeafVersion,
    };
    use strata_asm_checkpoint_types::test_utils::create_test_checkpoint_payload;
    use strata_asm_proto_txs_test_utils::{
        create_reveal_transaction_stub_with_leaf, parse_sps50_tx,
    };
    use strata_codec::encode_to_vec;
    use strata_l1_envelope_fmt::SignedEnvelopeSpendError;

    use super::*;
    use crate::OL_STF_CHECKPOINT_TX_TAG;

    /// `OP_SUCCESS80` in tapscript, `OP_RESERVED` in legacy script. Its presence anywhere in a
    /// tapscript makes the script succeed without executing.
    const OP_SUCCESS80: u8 = 0x50;

    fn envelope_pubkey() -> XOnlyPublicKey {
        let keypair = Keypair::from_seckey_slice(SECP256K1, &[0x42; 32]).expect("valid secret key");
        keypair.x_only_public_key().0
    }

    fn checkpoint_payload_bytes() -> (CheckpointPayload, Vec<u8>) {
        let payload = create_test_checkpoint_payload(1);
        let bytes =
            encode_to_vec(&CodecSsz::new(payload.clone())).expect("checkpoint payload encodes");
        (payload, bytes)
    }

    fn reveal_tx(leaf_version: LeafVersion) -> Transaction {
        let (_, bytes) = checkpoint_payload_bytes();
        create_reveal_transaction_stub_with_leaf(
            &envelope_pubkey(),
            &bytes,
            &OL_STF_CHECKPOINT_TX_TAG,
            leaf_version,
        )
    }

    /// Every leaf version a control block can encode: even bytes, excluding the annex tag `0x50`.
    fn all_leaf_versions() -> impl Iterator<Item = LeafVersion> {
        (0..=u8::MAX)
            .step_by(2)
            .filter_map(|byte| LeafVersion::from_consensus(byte).ok())
    }

    #[test]
    fn parses_pubkey_payload_and_spent_outpoint() {
        let (payload, bytes) = checkpoint_payload_bytes();
        let tx = reveal_tx(LeafVersion::TapScript);

        let spend = parse_checkpoint_envelope(&parse_sps50_tx(&tx))
            .expect("TapScript leaf carrying a valid envelope parses");

        assert_eq!(
            spend.unverified_leaf().pubkey(),
            &envelope_pubkey().serialize()
        );
        assert_eq!(spend.unverified_leaf().payload(), bytes.as_slice());
        assert_eq!(spend.spent_outpoint(), tx.input[0].previous_output);
        assert_eq!(
            decode_checkpoint_payload(spend.unverified_leaf().payload()).expect("payload decodes"),
            payload
        );
    }

    #[test]
    fn extracts_payload() {
        let (payload, _) = checkpoint_payload_bytes();
        let tx = reveal_tx(LeafVersion::TapScript);

        let extracted =
            extract_checkpoint_from_envelope(&parse_sps50_tx(&tx)).expect("envelope parses");

        assert_eq!(extracted, payload);
    }

    /// Bitcoin runs no leaf version but `TapScript`, so no other version carries a checkpoint
    /// envelope.
    #[test]
    fn non_tapscript_leaf_versions_are_rejected() {
        let non_tapscript = all_leaf_versions().filter(|v| *v != LeafVersion::TapScript);
        for leaf_version in non_tapscript {
            let result = parse_checkpoint_envelope(&parse_sps50_tx(&reveal_tx(leaf_version)));

            let expected = leaf_version.to_consensus();
            assert!(
                matches!(
                    result,
                    Err(CheckpointTxError::EnvelopeSpend(
                        SignedEnvelopeSpendError::UnsupportedLeafVersion { version }
                    )) if version == expected
                ),
                "leaf version {expected:#04x} must be rejected, got {result:?}"
            );
        }
    }

    /// Replaces the leaf script in the envelope input's `[signature, leaf script, control
    /// block]` witness. The control block no longer commits to the new script, which the
    /// parser does not check.
    fn with_leaf_script(tx: &Transaction, leaf_script: &[u8]) -> Transaction {
        let mut tx = tx.clone();
        let witness = &tx.input[0].witness;
        let signature = witness.nth(0).expect("signature").to_vec();
        let control_block = witness.nth(2).expect("control block").to_vec();
        tx.input[0].witness =
            Witness::from_slice(&[signature.as_slice(), leaf_script, control_block.as_slice()]);
        tx
    }

    /// The envelope pubkey authenticates only because the strict leaf shape
    /// `<pubkey> OP_CHECKSIG OP_FALSE OP_IF <data pushes> OP_ENDIF` leaves a valid signature as
    /// the only way to satisfy the script. That strictness lives in `strata-l1-envelope-fmt`;
    /// these cases pin it, so a dependency update that relaxes it fails here. Each mutated leaf
    /// would let a TapScript spend succeed without the key's signature.
    #[test]
    fn leaves_spendable_without_a_signature_are_rejected() {
        let tx = reveal_tx(LeafVersion::TapScript);
        let leaf = tx.input[0]
            .witness
            .nth(1)
            .expect("reveal witness has its leaf script")
            .to_vec();
        // Guard the byte offsets the mutations below rely on.
        assert_eq!(leaf[0], OP_PUSHBYTES_32.to_u8());
        assert_eq!(leaf[33], OP_CHECKSIG.to_u8());
        assert_eq!(leaf[34], OP_PUSHBYTES_0.to_u8());
        assert_eq!(leaf[35], OP_IF.to_u8());
        assert_eq!(leaf.last(), Some(&OP_ENDIF.to_u8()));

        // An empty signature makes OP_CHECKSIG push false, and OP_NOT turns it into true.
        let mut trailing_not = leaf.clone();
        trailing_not.push(OP_NOT.to_u8());

        // OP_SUCCESS80 succeeds the whole script even inside the unexecuted branch.
        let mut success_in_envelope = leaf.clone();
        success_in_envelope.insert(leaf.len() - 1, OP_SUCCESS80);

        // Without OP_CHECKSIG the pubkey is just data.
        let mut no_checksig = leaf.clone();
        no_checksig.remove(33);

        let cases = [
            ("OP_NOT after OP_ENDIF", trailing_not),
            ("OP_SUCCESS80 inside the envelope", success_in_envelope),
            ("OP_CHECKSIG removed", no_checksig),
        ];
        for (case, leaf_script) in cases {
            let mutated = with_leaf_script(&tx, &leaf_script);

            let result = parse_checkpoint_envelope(&parse_sps50_tx(&mutated));

            assert!(
                matches!(
                    result,
                    Err(CheckpointTxError::EnvelopeSpend(
                        SignedEnvelopeSpendError::InvalidLeaf(_)
                    ))
                ),
                "{case}: leaf must be rejected, got {result:?}"
            );
        }
    }
}
