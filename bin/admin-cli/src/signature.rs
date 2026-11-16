//! Signer keys and signatures as they appear on the command line.

use std::str::FromStr;

use anyhow::{Context, anyhow};
use bitcoin::{
    base64::{Engine, engine::general_purpose::STANDARD as BASE64},
    bip32::Xpriv,
    secp256k1::SecretKey,
};
use strata_asm_admin_threshold_sig::IndexedSignature;

/// Length of a BIP-137 signature: a header byte, then `r` and `s`.
const BIP137_SIG_LEN: usize = 65;

/// Parses a signer key given as a BIP-32 xpriv or 32 hex-encoded bytes.
///
/// An xpriv signs with its own key. No derivation path is applied.
pub(crate) fn parse_secret_key(value: &str) -> anyhow::Result<SecretKey> {
    let value = value.trim();
    if let Ok(xpriv) = Xpriv::from_str(value) {
        return Ok(xpriv.private_key);
    }
    let bytes = hex::decode(value).context("key is neither an xpriv nor hex")?;
    SecretKey::from_slice(&bytes).context("key is not a valid 32-byte secret key")
}

/// Encodes a signature the way `signmessage` prints it.
pub(crate) fn encode_signature(signature: &[u8; BIP137_SIG_LEN]) -> String {
    BASE64.encode(signature)
}

/// Parses `<signer index>:<base64 signature>`.
///
/// The header byte is kept as the wallet wrote it. The chain accepts the raw (0-3),
/// compressed P2PKH (31-34), P2SH-P2WPKH (35-38) and P2WPKH (39-42) headers.
pub(crate) fn parse_indexed_signature(spec: &str) -> anyhow::Result<IndexedSignature> {
    let (index, value) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("expected `<signer index>:<base64 signature>`"))?;
    let index: u8 = index
        .parse()
        .with_context(|| format!("invalid signer index `{index}`"))?;
    let bytes = BASE64
        .decode(value.trim())
        .with_context(|| format!("signature for signer {index} is not base64"))?;
    let signature: [u8; BIP137_SIG_LEN] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "signature for signer {index} is {} bytes, expected {BIP137_SIG_LEN}",
            bytes.len()
        )
    })?;
    Ok(IndexedSignature::new(index, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_xpriv_keys() {
        let key = parse_secret_key(&hex::encode([7; 32])).unwrap();
        assert_eq!(key.secret_bytes(), [7; 32]);

        let xpriv = "tprv8ZgxMBicQKsPd4arFr7sKjSnKFDVMR2JHw9Y8L9nXN4kiok4u28LpHijEudH3mMYoL4pM5UL9Bgdz2M4Cy8EzfErmU9m86ZTw6hCzvFeTg7";
        let key = parse_secret_key(xpriv).unwrap();
        assert_eq!(key, Xpriv::from_str(xpriv).unwrap().private_key);

        assert!(parse_secret_key("zz").is_err());
        assert!(parse_secret_key(&hex::encode([7; 31])).is_err());
    }

    #[test]
    fn round_trips_a_signature() {
        let signature = [9; BIP137_SIG_LEN];
        let parsed = parse_indexed_signature(&format!("2:{}", encode_signature(&signature)));
        assert_eq!(parsed.unwrap(), IndexedSignature::new(2, signature));
    }

    #[test]
    fn rejects_malformed_signatures() {
        for spec in ["AAAA", "x:AAAA", "256:AAAA", "0:!!!", "0:AAAA"] {
            assert!(parse_indexed_signature(spec).is_err(), "{spec}");
        }
    }
}
