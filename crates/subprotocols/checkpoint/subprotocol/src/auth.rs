//! Authentication of checkpoint envelopes.
//!
//! The ASM verifies no signature over a checkpoint. Following SPS-51, it accepts the envelope
//! pubkey in place of one, on the grounds that Bitcoin verified a signature by that pubkey when
//! it accepted the carrier transaction. That holds only for a strict signed envelope leaf, under
//! the tapscript leaf version, spending a native P2TR output.
//!
//! Parsing and authentication are separate steps. Parsing
//! ([`parse_checkpoint_envelope`]) reads the envelope spend from the transaction; the leaf shape
//! and leaf version are part of its format, so a [`SignedEnvelopeSpend`] already satisfies them.
//! Authentication ([`authenticate_checkpoint_envelope`]) adds what the transaction alone cannot
//! show: the pubkey must be the sequencer key, and the spent output, which reaches the ASM only
//! through aux data, must be native P2TR. Pre-process runs only the key check
//! ([`verify_envelope_key`]) to decide which spent outputs to request.

use strata_asm_checkpoint_types::CheckpointPayload;
use strata_asm_common::{TxInputRef, VerifiedAuxData};
use strata_asm_proto_checkpoint_txs::{decode_checkpoint_payload, parse_checkpoint_envelope};
use strata_checkpoint_verification::verify_sequencer_key;
use strata_identifiers::Buf32;
use strata_l1_envelope_fmt::{SignedEnvelopeLeaf, SignedEnvelopeSpend};

use crate::errors::CheckpointEnvelopeError;

/// Checks that the envelope pubkey of `spend` is `sequencer_key`.
///
/// This needs no aux data, so pre-process uses it to decide whether to request the spent
/// output. It does not authenticate the envelope; see [`authenticate_checkpoint_envelope`].
///
/// # Errors
///
/// [`CheckpointEnvelopeError::SequencerKey`] if the envelope pubkey is not `sequencer_key`.
pub fn verify_envelope_key(
    sequencer_key: &Buf32,
    spend: &SignedEnvelopeSpend,
) -> Result<(), CheckpointEnvelopeError> {
    verify_sequencer_key(sequencer_key, spend.unverified_leaf().pubkey())?;
    Ok(())
}

/// Authenticates a parsed checkpoint envelope as the sequencer's and returns its leaf.
///
/// Checks that the envelope pubkey is `sequencer_key` and that the output the envelope input
/// spends, read from `verified_aux_data`, is a native P2TR output. `verified_aux_data` must carry
/// the transaction spent by the envelope input; pre-process requests it for every envelope that
/// passes [`verify_envelope_key`].
///
/// # Errors
///
/// [`CheckpointEnvelopeError::MissingSpentOutput`] if `verified_aux_data` lacks the spent output,
/// which means the aux request was not honored. Every other variant means the envelope is not
/// the sequencer's.
pub fn authenticate_checkpoint_envelope(
    sequencer_key: &Buf32,
    spend: SignedEnvelopeSpend,
    verified_aux_data: &VerifiedAuxData,
) -> Result<SignedEnvelopeLeaf, CheckpointEnvelopeError> {
    verify_envelope_key(sequencer_key, &spend)?;

    let outpoint = spend.spent_outpoint();
    let spent_output = verified_aux_data
        .get_bitcoin_txout(&outpoint)
        .map_err(|source| CheckpointEnvelopeError::MissingSpentOutput { outpoint, source })?;
    Ok(spend.verify_spent_output(&spent_output.script_pubkey)?)
}

/// Parses, authenticates and decodes the checkpoint in `tx`.
///
/// Composes [`parse_checkpoint_envelope`], [`authenticate_checkpoint_envelope`] and
/// [`decode_checkpoint_payload`], for consumers that need the authenticated payload in one call.
///
/// # Errors
///
/// [`CheckpointEnvelopeError::Envelope`] if `tx` carries no checkpoint envelope or its payload
/// does not decode, and the errors of [`authenticate_checkpoint_envelope`].
pub fn authenticate_checkpoint_tx(
    sequencer_key: &Buf32,
    tx: &TxInputRef<'_>,
    verified_aux_data: &VerifiedAuxData,
) -> Result<CheckpointPayload, CheckpointEnvelopeError> {
    let spend = parse_checkpoint_envelope(tx)?;
    let leaf = authenticate_checkpoint_envelope(sequencer_key, spend, verified_aux_data)?;
    Ok(decode_checkpoint_payload(leaf.payload())?)
}

#[cfg(test)]
mod tests {
    use bitcoin::{XOnlyPublicKey, key::Keypair, secp256k1::SECP256K1, taproot::LeafVersion};
    use strata_asm_proto_checkpoint_txs::CheckpointTxError;
    use strata_asm_proto_txs_test_utils::parse_sps50_tx;
    use strata_checkpoint_verification::CheckpointValidationError;
    use strata_l1_envelope_fmt::SignedEnvelopeSpendError;

    use super::*;
    use crate::test_utils::{CheckpointFixture, p2tr_script, witness_v2_script};

    fn other_key() -> XOnlyPublicKey {
        Keypair::from_seckey_slice(SECP256K1, &[0x42; 32])
            .expect("valid secret key")
            .x_only_public_key()
            .0
    }

    #[test]
    fn sequencer_envelope_spending_p2tr_authenticates() {
        let fixture = CheckpointFixture::new();
        let (funding, carrier) = fixture.build_carrier(
            &fixture.sequencer_key(),
            LeafVersion::TapScript,
            p2tr_script(),
        );

        let payload = authenticate_checkpoint_tx(
            fixture.state.sequencer_key(),
            &parse_sps50_tx(&carrier),
            &fixture.verified_aux(&funding),
        )
        .expect("sequencer envelope spending P2TR authenticates");

        assert_eq!(payload.new_tip(), &fixture.new_tip);
    }

    /// Bitcoin never runs a witness spending an unencumbered output, so the envelope pubkey
    /// proves nothing about who built the carrier.
    #[test]
    fn unencumbered_spent_output_is_rejected() {
        let fixture = CheckpointFixture::new();
        let (funding, carrier) = fixture.build_carrier(
            &fixture.sequencer_key(),
            LeafVersion::TapScript,
            witness_v2_script(),
        );

        let result = authenticate_checkpoint_tx(
            fixture.state.sequencer_key(),
            &parse_sps50_tx(&carrier),
            &fixture.verified_aux(&funding),
        );

        assert!(
            matches!(
                result,
                Err(CheckpointEnvelopeError::SpentOutput(
                    SignedEnvelopeSpendError::NonTaprootSpentOutput { .. }
                ))
            ),
            "unexpected result: {result:?}"
        );
    }

    /// Bitcoin runs no leaf version but tapscript, so no other version authenticates, even
    /// spending P2TR.
    #[test]
    fn future_leaf_version_is_rejected() {
        let fixture = CheckpointFixture::new();
        let future = LeafVersion::from_consensus(0xc2).expect("0xc2 is a future leaf version");
        let (funding, carrier) =
            fixture.build_carrier(&fixture.sequencer_key(), future, p2tr_script());

        let result = authenticate_checkpoint_tx(
            fixture.state.sequencer_key(),
            &parse_sps50_tx(&carrier),
            &fixture.verified_aux(&funding),
        );

        assert!(
            matches!(
                result,
                Err(CheckpointEnvelopeError::Envelope(
                    CheckpointTxError::EnvelopeSpend(
                        SignedEnvelopeSpendError::UnsupportedLeafVersion { version: 0xc2 }
                    )
                ))
            ),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn non_sequencer_key_is_rejected_without_aux() {
        let fixture = CheckpointFixture::new();
        let (_, carrier) =
            fixture.build_carrier(&other_key(), LeafVersion::TapScript, p2tr_script());

        let spend = parse_checkpoint_envelope(&parse_sps50_tx(&carrier)).expect("envelope parses");
        // No funding transaction in aux: the key check must reject before the aux lookup.
        let aux_without_funding = fixture.harness.gen_verified_aux(&fixture.new_tip);

        let result = authenticate_checkpoint_envelope(
            fixture.state.sequencer_key(),
            spend,
            &aux_without_funding,
        );

        assert!(
            matches!(
                result,
                Err(CheckpointEnvelopeError::SequencerKey(
                    CheckpointValidationError::InvalidSequencerKey(_)
                ))
            ),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn missing_spent_output_is_reported() {
        let fixture = CheckpointFixture::new();
        let (_, carrier) = fixture.build_carrier(
            &fixture.sequencer_key(),
            LeafVersion::TapScript,
            p2tr_script(),
        );
        let aux_without_funding = fixture.harness.gen_verified_aux(&fixture.new_tip);

        let result = authenticate_checkpoint_tx(
            fixture.state.sequencer_key(),
            &parse_sps50_tx(&carrier),
            &aux_without_funding,
        );

        let spent = carrier.input[0].previous_output;
        assert!(
            matches!(
                result,
                Err(CheckpointEnvelopeError::MissingSpentOutput { outpoint, .. }) if outpoint == spent
            ),
            "unexpected result: {result:?}"
        );
    }
}
