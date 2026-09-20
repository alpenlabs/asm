//! P2WPKH address identifying an administration threshold signer.

use bitcoin::{
    Address, CompressedPublicKey, Network, WPubkeyHash, WitnessProgram, WitnessVersion,
    address::NetworkUnchecked, hashes::Hash as _,
};
use secp256k1::PublicKey;
use ssz::{Decode, DecodeError, Encode};
use thiserror::Error;

/// Length of a P2WPKH witness program.
const WITNESS_PROGRAM_LEN: usize = 20;

/// The P2WPKH witness program identifying an authorized administration signer.
///
/// Signers are named by address rather than by public key because a hardware wallet will
/// show an address on its screen but not a compressed public key. A signer can read their
/// own identifier off the device and compare it with what the tooling shows them.
///
/// The stored value is the bare 20-byte witness program, the `hash160` of the signer's
/// compressed public key. The network is deliberately not part of the identity: `bc1q...`
/// and `tb1q...` over the same program authorize the same key. The bech32 form is produced
/// only at presentation boundaries, from the network the chain is anchored to.
///
/// Unlike a public key, every 20-byte value is a well-formed program, so decoding cannot
/// reject a nonsense signer the way a curve-point check could. A program nobody holds the
/// preimage of is simply a signer that can never sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct P2wpkhAddress(WPubkeyHash);

impl P2wpkhAddress {
    /// Derives the address of the signer holding `pubkey`.
    ///
    /// The key is always hashed in its compressed form, since P2WPKH is only defined for
    /// compressed keys. This is the authoritative derivation: signature verification
    /// recovers a key from the signature and compares the result of this function against
    /// the configured signer.
    pub fn from_pubkey(pubkey: &PublicKey) -> Self {
        Self(CompressedPublicKey(*pubkey).wpubkey_hash())
    }

    /// Creates an address from a raw witness program.
    pub fn from_byte_array(program: [u8; WITNESS_PROGRAM_LEN]) -> Self {
        Self(WPubkeyHash::from_byte_array(program))
    }

    /// Extracts the signer address from a parsed Bitcoin address.
    ///
    /// The network the address was written for is ignored: `bc1q...` and `tb1q...` over the
    /// same program name the same signer. Whether an address belongs to the network the
    /// chain runs on is a question about the parameter file, checked when it is loaded.
    ///
    /// # Errors
    ///
    /// Returns [`NotP2wpkhAddress`] if `address` is not pay-to-witness-public-key-hash.
    pub fn try_from_address(address: &Address<NetworkUnchecked>) -> Result<Self, NotP2wpkhAddress> {
        let program = address
            .assume_checked_ref()
            .witness_program()
            .filter(WitnessProgram::is_p2wpkh)
            .ok_or(NotP2wpkhAddress)?;

        Ok(Self(
            WPubkeyHash::from_slice(program.program().as_bytes())
                .expect("a P2WPKH witness program is 20 bytes"),
        ))
    }

    /// Renders the address in its bech32 form for `network`.
    pub fn to_address(&self, network: Network) -> Address {
        let program = WitnessProgram::new(WitnessVersion::V0, self.0.as_byte_array())
            .expect("a 20-byte v0 witness program is valid");
        Address::from_witness_program(program, network)
    }

    /// Returns the raw 20-byte witness program.
    pub fn to_byte_array(&self) -> [u8; WITNESS_PROGRAM_LEN] {
        self.0.to_byte_array()
    }
}

/// A Bitcoin address that cannot name an administration signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("signer address must be P2WPKH")]
pub struct NotP2wpkhAddress;

// Byte layout: the raw 20-byte witness program, with no length prefix.
impl Encode for P2wpkhAddress {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        WITNESS_PROGRAM_LEN
    }

    fn ssz_bytes_len(&self) -> usize {
        WITNESS_PROGRAM_LEN
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0.as_byte_array());
    }
}

impl Decode for P2wpkhAddress {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        WITNESS_PROGRAM_LEN
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let program: [u8; WITNESS_PROGRAM_LEN] =
            bytes
                .try_into()
                .map_err(|_| DecodeError::InvalidByteLength {
                    len: bytes.len(),
                    expected: WITNESS_PROGRAM_LEN,
                })?;
        Ok(Self::from_byte_array(program))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for P2wpkhAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut program = [0u8; WITNESS_PROGRAM_LEN];
        u.fill_buffer(&mut program)?;
        Ok(Self::from_byte_array(program))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use secp256k1::{SECP256K1, SecretKey};
    use ssz::{Decode, Encode};

    use super::*;

    /// Public key of the secp256k1 generator point, whose P2WPKH address is a well-known
    /// BIP-173 test vector.
    fn generator_pubkey() -> PublicKey {
        let sk = SecretKey::from_slice(&{
            let mut bytes = [0u8; 32];
            bytes[31] = 1;
            bytes
        })
        .expect("1 is a valid scalar");
        PublicKey::from_secret_key(SECP256K1, &sk)
    }

    /// Pins the derivation against the BIP-173 example, which is the P2WPKH address of the
    /// generator point on mainnet. A change here would silently repoint every signer.
    #[test]
    fn from_pubkey_matches_the_bip173_vector() {
        let signer = P2wpkhAddress::from_pubkey(&generator_pubkey());

        assert_eq!(
            hex::encode(signer.to_byte_array()),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert_eq!(
            signer.to_address(Network::Bitcoin).to_string(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    #[test]
    fn to_address_uses_the_networks_prefix() {
        let signer = P2wpkhAddress::from_pubkey(&generator_pubkey());

        assert!(
            signer
                .to_address(Network::Bitcoin)
                .to_string()
                .starts_with("bc1q")
        );
        assert!(
            signer
                .to_address(Network::Testnet)
                .to_string()
                .starts_with("tb1q")
        );
        assert!(
            signer
                .to_address(Network::Regtest)
                .to_string()
                .starts_with("bcrt1q")
        );
    }

    #[test]
    fn try_from_address_roundtrips_through_bech32() {
        let signer = P2wpkhAddress::from_pubkey(&generator_pubkey());
        let rendered = signer.to_address(Network::Regtest).to_string();
        let parsed = Address::from_str(&rendered).expect("rendered address parses");

        assert_eq!(P2wpkhAddress::try_from_address(&parsed), Ok(signer));
    }

    /// The same program written for two networks names one signer, which is why the
    /// network is not part of the identity.
    #[test]
    fn try_from_address_ignores_the_network_it_was_written_for() {
        let signer = P2wpkhAddress::from_pubkey(&generator_pubkey());
        let mainnet = Address::from_str(&signer.to_address(Network::Bitcoin).to_string())
            .expect("rendered address parses");
        let regtest = Address::from_str(&signer.to_address(Network::Regtest).to_string())
            .expect("rendered address parses");

        assert_eq!(P2wpkhAddress::try_from_address(&mainnet), Ok(signer));
        assert_eq!(P2wpkhAddress::try_from_address(&regtest), Ok(signer));
    }

    #[test]
    fn try_from_address_rejects_a_non_p2wpkh_address() {
        // A P2WSH address: segwit v0, but a 32-byte program.
        let p2wsh =
            Address::from_str("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
                .expect("BIP-173 P2WSH vector parses");

        assert_eq!(
            P2wpkhAddress::try_from_address(&p2wsh),
            Err(NotP2wpkhAddress)
        );
    }

    #[test]
    fn ssz_encodes_as_the_bare_witness_program() {
        let signer = P2wpkhAddress::from_pubkey(&generator_pubkey());
        let encoded = signer.as_ssz_bytes();

        assert_eq!(encoded, signer.to_byte_array().to_vec());
        assert_eq!(P2wpkhAddress::from_ssz_bytes(&encoded), Ok(signer));
    }

    #[test]
    fn ssz_rejects_a_wrong_length() {
        assert!(P2wpkhAddress::from_ssz_bytes(&[0u8; 19]).is_err());
        assert!(P2wpkhAddress::from_ssz_bytes(&[0u8; 21]).is_err());
    }

    #[test]
    fn equal_addresses_hash_equally() {
        use std::collections::HashSet;

        let signers: HashSet<_> = [
            P2wpkhAddress::from_byte_array([1u8; 20]),
            P2wpkhAddress::from_byte_array([1u8; 20]),
            P2wpkhAddress::from_byte_array([2u8; 20]),
        ]
        .into_iter()
        .collect();

        assert_eq!(signers.len(), 2);
    }
}
