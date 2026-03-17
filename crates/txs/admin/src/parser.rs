use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use strata_asm_common::{
    TxInputRef, from_ssz_bytes_via_serde_json, ssz_append_via_serde_json,
    ssz_bytes_len_via_serde_json,
};
use strata_crypto::threshold_signature::{IndexedSignature, SignatureSet};
use strata_l1_envelope_fmt::parser::parse_envelope_payload;

use crate::{actions::MultisigAction, errors::AdministrationTxParseError};

/// A signed administration payload containing both the action and its signatures.
///
/// This structure is serialized with SSZ and embedded in the witness envelope.
/// The OP_RETURN only contains the SPS-50 tag (magic bytes, subprotocol ID, tx type).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPayload {
    /// Sequence number used to prevent replay attacks and enforce ordering.
    pub seqno: u64,
    /// The administrative action being proposed
    pub action: MultisigAction,
    /// The set of ECDSA signatures authorizing this action
    pub signatures: SignatureSet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SignedPayloadJson {
    seqno: u64,
    action: MultisigAction,
    signatures: Vec<IndexedSignatureJson>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IndexedSignatureJson {
    index: u8,
    signature: Vec<u8>,
}

impl Encode for SignedPayload {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        ssz_append_via_serde_json(&self.as_json(), buf, "signed admin payload");
    }

    fn ssz_bytes_len(&self) -> usize {
        ssz_bytes_len_via_serde_json(&self.as_json(), "signed admin payload")
    }
}

impl Decode for SignedPayload {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let payload: SignedPayloadJson = from_ssz_bytes_via_serde_json(bytes)?;
        Ok(Self::from_json(payload))
    }
}

impl SignedPayload {
    fn as_json(&self) -> SignedPayloadJson {
        SignedPayloadJson {
            seqno: self.seqno,
            action: self.action.clone(),
            signatures: self
                .signatures
                .signatures()
                .iter()
                .map(|signature| {
                    let mut encoded = [0u8; 65];
                    encoded[0] = signature.recovery_id();
                    encoded[1..33].copy_from_slice(signature.r());
                    encoded[33..65].copy_from_slice(signature.s());
                    IndexedSignatureJson {
                        index: signature.index(),
                        signature: encoded.to_vec(),
                    }
                })
                .collect(),
        }
    }

    fn from_json(payload: SignedPayloadJson) -> Self {
        let signatures = SignatureSet::new(
            payload
                .signatures
                .into_iter()
                .map(|signature| {
                    let encoded: [u8; 65] = signature
                        .signature
                        .try_into()
                        .expect("signed admin payload should preserve 65-byte signatures");
                    IndexedSignature::new(signature.index, encoded)
                })
                .collect(),
        )
        .expect("signed admin payload should preserve a valid signature set");
        Self {
            seqno: payload.seqno,
            action: payload.action,
            signatures,
        }
    }

    /// Creates a new signed payload combining an action with its signatures.
    pub fn new(seqno: u64, action: MultisigAction, signatures: SignatureSet) -> Self {
        Self {
            seqno,
            action,
            signatures,
        }
    }
}

/// Parses a transaction to extract both the multisig action and the signature set.
///
/// This function extracts the signed payload from the taproot leaf script embedded
/// in the transaction's witness data. The payload contains both the administrative
/// action and its authorizing signatures.
///
/// # Arguments
/// * `tx` - A reference to the transaction input to parse
///
/// # Errors
/// Returns `AdministrationTxParseError` if:
/// - The transaction lacks a taproot leaf script in its witness
/// - The envelope payload cannot be parsed
/// - The signed payload cannot be deserialized
// TODO: https://alpenlabs.atlassian.net/browse/STR-2366
pub fn parse_tx(tx: &TxInputRef<'_>) -> Result<SignedPayload, AdministrationTxParseError> {
    let tx_type = tx.tag().tx_type();

    // Extract the taproot leaf script from the first input's witness
    let payload_script = tx.tx().input[0]
        .witness
        .taproot_leaf_script()
        .ok_or(AdministrationTxParseError::MalformedTransaction(tx_type))?
        .script;

    // Parse the envelope payload from the script
    let envelope_payload = parse_envelope_payload(&payload_script.into())?;

    // Deserialize the signed payload (action + signatures) from the envelope
    let signed_payload = SignedPayload::from_ssz_bytes(&envelope_payload)
        .map_err(|_| AdministrationTxParseError::MalformedTransaction(tx_type))?;

    Ok(signed_payload)
}
