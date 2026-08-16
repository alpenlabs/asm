use ssz::{Decode, Encode};
use ssz_derive::{Decode as DeriveDecode, Encode as DeriveEncode};
use strata_asm_admin_types::{AdminTxType, UpdateTxType};
use strata_asm_common::{TxInputRef, logging::warn};
use strata_crypto::threshold_signature::SignatureSet;
use strata_l1_envelope_fmt::parser::parse_envelope_payload;
use strata_l1_txfmt::TxType;

use crate::{
    actions::{
        CancelAction, MultisigAction, UpdateAction,
        updates::{
            AlpenAdminMultisigUpdate, AsmStfVkUpdate, Defcon1Update, Defcon3Update, EeStfVkUpdate,
            OlStfVkUpdate, OperatorSetUpdate, SafeHarbourAddressUpdate, SequencerUpdate,
            StrataAdminMultisigUpdate, StrataSecurityCouncilMultisigUpdate,
            StrataSeqManagerMultisigUpdate,
        },
    },
    errors::AdministrationTxParseError,
};

/// A signed administration payload containing both the action and its signatures.
///
/// In-memory representation handed to the subprotocol handler. On the wire the action is
/// encoded *without* enum discriminants: the SPS-50 tag's tx type selects the concrete
/// action type, and the envelope carries the corresponding [`SignedActionPayload`]. Use
/// [`into_envelope_bytes`](Self::into_envelope_bytes) / [`parse_tx`] to cross that
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPayload {
    /// Sequence number used to prevent replay attacks and enforce ordering.
    pub seqno: u64,
    /// The administrative action being proposed
    pub action: MultisigAction,
    /// The set of ECDSA signatures authorizing this action
    pub signatures: SignatureSet,
}

impl SignedPayload {
    /// Creates a new signed payload combining an action with its signatures.
    pub fn new(seqno: u64, action: MultisigAction, signatures: SignatureSet) -> Self {
        Self {
            seqno,
            action,
            signatures,
        }
    }

    /// Encodes this payload into the envelope wire format.
    ///
    /// The action is encoded without its enum discriminants; the receiver re-derives the
    /// concrete type from the SPS-50 tag's tx type, so the tag (see
    /// [`MultisigAction::tag`]) must be built from the same action.
    pub fn into_envelope_bytes(self) -> Vec<u8> {
        let Self {
            seqno,
            action,
            signatures,
        } = self;
        match action {
            MultisigAction::Cancel(action) => encode_wire(seqno, action, signatures),
            MultisigAction::Update(update) => match update {
                UpdateAction::StrataAdminMultisig(u) => encode_wire(seqno, u, signatures),
                UpdateAction::StrataSeqManagerMultisig(u) => encode_wire(seqno, u, signatures),
                UpdateAction::AlpenAdminMultisig(u) => encode_wire(seqno, u, signatures),
                UpdateAction::StrataSecurityCouncilMultisig(u) => encode_wire(seqno, u, signatures),
                UpdateAction::OperatorSet(u) => encode_wire(seqno, u, signatures),
                UpdateAction::Sequencer(u) => encode_wire(seqno, u, signatures),
                UpdateAction::OlStfVk(u) => encode_wire(seqno, u, signatures),
                UpdateAction::AsmStfVk(u) => encode_wire(seqno, u, signatures),
                UpdateAction::EeStfVk(u) => encode_wire(seqno, u, signatures),
                UpdateAction::Defcon1(u) => encode_wire(seqno, u, signatures),
                UpdateAction::Defcon3(u) => encode_wire(seqno, u, signatures),
                UpdateAction::SafeHarbourAddress(u) => encode_wire(seqno, u, signatures),
            },
        }
    }
}

/// Wire-format container embedded in the envelope: the signed payload for one concrete
/// action type `A`.
///
/// The SPS-50 tag's tx type byte — not an encoded enum discriminant — determines `A`, so
/// the envelope carries no redundant selector bytes and each tx type has a flat,
/// self-describing SSZ schema that's easy to construct outside this codebase.
#[derive(DeriveEncode, DeriveDecode)]
struct SignedActionPayload<A: Encode + Decode> {
    seqno: u64,
    action: A,
    signatures: SignatureSet,
}

fn encode_wire<A: Encode + Decode>(seqno: u64, action: A, signatures: SignatureSet) -> Vec<u8> {
    SignedActionPayload {
        seqno,
        action,
        signatures,
    }
    .as_ssz_bytes()
}

/// Parses a transaction into a [`SignedPayload`] based on its SPS-50 tx type.
///
/// The tag's tx type selects the concrete action type to decode from the taproot leaf
/// script envelope in the transaction's witness; the payload itself carries no enum
/// discriminants.
///
/// # Returns
///
/// Returns `Some(SignedPayload)` when the tx type is known and the envelope payload is
/// well-formed, returns None (with a warning logged) otherwise.
pub fn parse_tx(tx: &TxInputRef<'_>) -> Option<SignedPayload> {
    // Decode the SPS-50 tag's tx type byte into a known `AdminTxType`. An unknown
    // discriminant means the tx was tagged for the administration subprotocol but with a
    // type this build doesn't recognize — likely a protocol/version mismatch.
    let raw_tx_type = tx.tag().tx_type();
    let admin_tx_type: AdminTxType = match raw_tx_type.try_into() {
        Ok(t) => t,
        Err(_) => {
            // `txid` is computed inside the macro, because logging is compiled to noop in ZkVM.
            warn!(
                txid = %tx.tx().compute_txid(),
                raw_tx_type,
                "Skipping tx with unsupported admin tx type",
            );
            return None;
        }
    };

    // Funnel structural failures through one shared log site. Admin txs are rare and
    // security-sensitive, so a malformed one is worth surfacing.
    match extract_signed_payload(tx, admin_tx_type) {
        Ok(payload) => Some(payload),
        Err(e) => {
            warn!(
                txid = %tx.tx().compute_txid(),
                error = %e,
                "Failed to parse admin tx; skipping",
            );
            None
        }
    }
}

/// Extracts the envelope payload from the witness and decodes it as the concrete action
/// type implied by `admin_tx_type`.
fn extract_signed_payload(
    tx: &TxInputRef<'_>,
    admin_tx_type: AdminTxType,
) -> Result<SignedPayload, AdministrationTxParseError> {
    let tx_type = tx.tag().tx_type();

    // Extract the taproot leaf script from the first input's witness. Index through
    // `first()`: the tx is routed here on its output tag alone, so nothing upstream has
    // checked that it even has an input.
    let payload_script = tx
        .tx()
        .input
        .first()
        .and_then(|input| input.witness.taproot_leaf_script())
        .ok_or(AdministrationTxParseError::MissingPayloadScript(tx_type))?
        .script;

    // Parse the envelope payload from the script
    let envelope_payload = parse_envelope_payload(&payload_script.into())?;

    decode_signed_payload(admin_tx_type, &envelope_payload, tx_type)
}

/// Decodes the envelope payload as the concrete action type implied by the tx type.
///
/// The tag byte itself is not signed, but the action reconstructed from it is: a tag that
/// misrepresents its payload's type either fails to decode here or yields an action whose
/// signing message the signatures don't cover, failing verification in the handler.
fn decode_signed_payload(
    admin_tx_type: AdminTxType,
    bytes: &[u8],
    tx_type: TxType,
) -> Result<SignedPayload, AdministrationTxParseError> {
    match admin_tx_type {
        AdminTxType::Cancel => {
            let wire = decode_wire::<CancelAction>(bytes, tx_type)?;
            Ok(SignedPayload::new(
                wire.seqno,
                MultisigAction::Cancel(wire.action),
                wire.signatures,
            ))
        }
        AdminTxType::Update(update_type) => match update_type {
            UpdateTxType::StrataAdminMultisigUpdate => {
                decode_update::<StrataAdminMultisigUpdate>(bytes, tx_type)
            }
            UpdateTxType::StrataSeqManagerMultisigUpdate => {
                decode_update::<StrataSeqManagerMultisigUpdate>(bytes, tx_type)
            }
            UpdateTxType::AlpenAdminMultisigUpdate => {
                decode_update::<AlpenAdminMultisigUpdate>(bytes, tx_type)
            }
            UpdateTxType::StrataSecurityCouncilMultisigUpdate => {
                decode_update::<StrataSecurityCouncilMultisigUpdate>(bytes, tx_type)
            }
            UpdateTxType::OperatorUpdate => decode_update::<OperatorSetUpdate>(bytes, tx_type),
            UpdateTxType::SequencerUpdate => decode_update::<SequencerUpdate>(bytes, tx_type),
            UpdateTxType::OlStfVkUpdate => decode_update::<OlStfVkUpdate>(bytes, tx_type),
            UpdateTxType::AsmStfVkUpdate => decode_update::<AsmStfVkUpdate>(bytes, tx_type),
            UpdateTxType::EeStfVkUpdate => decode_update::<EeStfVkUpdate>(bytes, tx_type),
            UpdateTxType::Defcon1 => decode_update::<Defcon1Update>(bytes, tx_type),
            UpdateTxType::Defcon3 => decode_update::<Defcon3Update>(bytes, tx_type),
            UpdateTxType::SafeHarbourAddressUpdate => {
                decode_update::<SafeHarbourAddressUpdate>(bytes, tx_type)
            }
        },
    }
}

fn decode_update<A>(
    bytes: &[u8],
    tx_type: TxType,
) -> Result<SignedPayload, AdministrationTxParseError>
where
    A: Encode + Decode + Into<UpdateAction>,
{
    let wire = decode_wire::<A>(bytes, tx_type)?;
    Ok(SignedPayload::new(
        wire.seqno,
        MultisigAction::Update(wire.action.into()),
        wire.signatures,
    ))
}

fn decode_wire<A: Encode + Decode>(
    bytes: &[u8],
    tx_type: TxType,
) -> Result<SignedActionPayload<A>, AdministrationTxParseError> {
    // Preserve the underlying decode error so a malformed governance tx is diagnosable
    // from the logs.
    SignedActionPayload::from_ssz_bytes(bytes).map_err(|e| {
        AdministrationTxParseError::MalformedPayload {
            tx_type,
            reason: format!("{e:?}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use strata_asm_proto_txs_test_utils::{create_dummy_tx, overwrite_aux_data, parse_sps50_tx};
    use strata_crypto::threshold_signature::IndexedSignature;
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;
    use crate::{actions::RenderSigningMessage, constants::ADMINISTRATION_SUBPROTOCOL_ID};

    fn dummy_signatures() -> SignatureSet {
        let sigs = vec![
            IndexedSignature::new(0, [1u8; 65]),
            IndexedSignature::new(2, [2u8; 65]),
        ];
        SignatureSet::new(sigs).expect("valid signature set")
    }

    /// Round-trips arbitrary actions through the discriminant-free wire format, keyed by
    /// the same tx type the SPS-50 tag would carry.
    #[test]
    fn envelope_bytes_roundtrip() {
        let mut arb = ArbitraryGenerator::new();
        for _ in 0..64 {
            let action: MultisigAction = arb.generate();
            let admin_tx_type = action.tx_type();

            let original = SignedPayload::new(7, action, dummy_signatures());
            let bytes = original.clone().into_envelope_bytes();

            let decoded = decode_signed_payload(admin_tx_type, &bytes, admin_tx_type.into())
                .expect("wire payload must decode under its own tx type");
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn malformed_payload_is_rejected() {
        let garbage = [0xffu8; 7];
        for admin_tx_type in [
            AdminTxType::Cancel,
            AdminTxType::Update(UpdateTxType::SequencerUpdate),
        ] {
            let res = decode_signed_payload(admin_tx_type, &garbage, admin_tx_type.into());
            assert!(matches!(
                res,
                Err(AdministrationTxParseError::MalformedPayload { .. })
            ));
        }
    }

    /// Transactions are routed to this subprotocol on their output tag alone, so one with
    /// no inputs at all can reach the parser. It must be skipped rather than indexed into.
    #[test]
    fn zero_input_tx_is_skipped() {
        let mut tx = create_dummy_tx(0, 1);
        overwrite_aux_data(
            &mut tx,
            ADMINISTRATION_SUBPROTOCOL_ID,
            AdminTxType::Cancel.into(),
            vec![],
        );

        assert!(tx.input.is_empty());
        assert!(parse_tx(&parse_sps50_tx(&tx)).is_none());
    }
}
