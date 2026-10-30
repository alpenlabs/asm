//! Safe harbor address.
//!
//! A safe harbor is a Bitcoin output script descriptor used to redirect flows
//! under emergency conditions. Activation (via Defcon signals) is restricted to
//! the strata security council; address rotation is restricted to the strata
//! administrator, so the same authority cannot both trigger a sweep and pick
//! its destination. Once activated, the address is frozen — further rotation
//! is rejected so bridge nodes always observe a single destination.

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
#[cfg(feature = "arbitrary")]
use bitcoin::secp256k1::{Keypair, SECP256K1, SecretKey};
use bitcoin::{Address, Network, WitnessProgram, address::NetworkUnchecked};
use bitcoin_bosd::{Descriptor, DescriptorType, descriptor::P2TR_LEN};
use serde::{Deserialize, Serialize, de::Error as _};
use ssz::{Decode as SszDecode, DecodeError};
use ssz_derive::{Decode, Encode};
use thiserror::Error;

/// A safe harbor [`Descriptor`] restricted to taproot (P2TR) outputs.
///
/// Operators write and read the safe harbor as a bech32m address, because that is what a
/// wallet or hardware signer shows. The stored form is the descriptor, which has no network.
/// The address is produced only at presentation boundaries, from the network the chain is
/// anchored to.
///
/// Constructible only via [`TryFrom<Descriptor>`] and
/// [`try_from_address`](Self::try_from_address). Deserialization, SSZ
/// decoding, and the `arbitrary`-gated [`Arbitrary`] impl all enforce the
/// P2TR check so the invariant cannot be bypassed by supplying arbitrary
/// wire bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encode)]
pub struct SafeHarborAddress(Descriptor);

/// Wire-format wrapper that decodes a descriptor without imposing the P2TR
/// invariant during parsing. The check happens after decoding so [`Deserialize`]
/// and [`SszDecode`] for [`SafeHarborAddress`] can share the validation in
/// [`TryFrom<Descriptor>`].
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Decode)]
struct SafeHarborAddressRaw(Descriptor);

impl SafeHarborAddress {
    /// Extracts the safe harbor from a parsed Bitcoin address.
    ///
    /// The descriptor has no network, so the network the address was written for is
    /// ignored: `bc1p...` and `bcrt1p...` over the same output key name the same safe
    /// harbor. Whether an address belongs to the network the chain runs on is a question
    /// about the parameter file, checked when it is loaded.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSafeHarborAddress::NotP2tr`] if `address` is not pay-to-taproot, and
    /// [`InvalidSafeHarborAddress::InvalidOutputKey`] if its output key is not a valid x-only
    /// public key.
    pub fn try_from_address(
        address: &Address<NetworkUnchecked>,
    ) -> Result<Self, InvalidSafeHarborAddress> {
        let program = address
            .assume_checked_ref()
            .witness_program()
            .filter(WitnessProgram::is_p2tr)
            .ok_or(InvalidSafeHarborAddress::NotP2tr)?;
        let output_key: &[u8; P2TR_LEN] = program
            .program()
            .as_bytes()
            .try_into()
            .expect("a P2TR witness program is 32 bytes");

        // An address only checksums its program, so a 32-byte value off the curve still
        // parses. Nothing can spend from it, and the descriptor refuses to hold one.
        Descriptor::new_p2tr(output_key)
            .map(Self)
            .map_err(|_| InvalidSafeHarborAddress::InvalidOutputKey)
    }

    /// Renders the safe harbor as a bech32m address for `network`.
    pub fn to_address(&self, network: Network) -> Address {
        self.0
            .to_address(network)
            .expect("a P2TR descriptor always holds a valid x-only public key")
    }

    /// Returns a reference to the underlying P2TR descriptor.
    pub fn as_descriptor(&self) -> &Descriptor {
        &self.0
    }

    /// Consumes the wrapper and returns the underlying P2TR descriptor.
    pub fn into_descriptor(self) -> Descriptor {
        self.0
    }
}

/// Error returned when constructing a [`SafeHarborAddress`] from a descriptor
/// whose type tag is not [`DescriptorType::P2tr`].
#[derive(Debug, Error, PartialEq)]
#[error("safe harbor address must be a P2TR descriptor, got {0:?}")]
pub struct NotP2trDescriptor(DescriptorType);

/// A Bitcoin address that cannot be a [`SafeHarborAddress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InvalidSafeHarborAddress {
    /// The address is not pay-to-taproot.
    #[error("safe harbor address must be a P2TR address")]
    NotP2tr,

    /// The address is pay-to-taproot, but its output key is not a point on the curve.
    #[error("safe harbor address has an output key that is not a valid x-only public key")]
    InvalidOutputKey,
}

impl TryFrom<Descriptor> for SafeHarborAddress {
    type Error = NotP2trDescriptor;

    fn try_from(descriptor: Descriptor) -> Result<Self, Self::Error> {
        let type_tag = descriptor.type_tag();
        if type_tag == DescriptorType::P2tr {
            Ok(SafeHarborAddress(descriptor))
        } else {
            Err(NotP2trDescriptor(type_tag))
        }
    }
}

impl<'de> Deserialize<'de> for SafeHarborAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let SafeHarborAddressRaw(descriptor) = SafeHarborAddressRaw::deserialize(deserializer)?;
        SafeHarborAddress::try_from(descriptor).map_err(D::Error::custom)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SafeHarborAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Derive a P2TR descriptor from a fresh secp256k1 keypair so the
        // x-only pubkey is always on the curve. The only realistic rejection
        // from `SecretKey::from_slice` is the all-zero scalar (overflow is
        // ~2^-128); patch that one case rather than re-drawing entropy.
        let mut secret_bytes = [0u8; 32];
        u.fill_buffer(&mut secret_bytes)?;
        if secret_bytes.iter().all(|&b| b == 0) {
            secret_bytes[31] = 1;
        }
        let secret_key =
            SecretKey::from_slice(&secret_bytes).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (x_only, _parity) = keypair.x_only_public_key();
        let descriptor = Descriptor::new_p2tr(&x_only.serialize())
            .expect("x-only pubkey from a valid secp256k1 keypair is always a valid P2TR payload");
        Ok(SafeHarborAddress(descriptor))
    }
}

impl SszDecode for SafeHarborAddress {
    fn is_ssz_fixed_len() -> bool {
        SafeHarborAddressRaw::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        SafeHarborAddressRaw::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let SafeHarborAddressRaw(descriptor) = SafeHarborAddressRaw::from_ssz_bytes(bytes)?;
        SafeHarborAddress::try_from(descriptor)
            .map_err(|e| DecodeError::BytesInvalid(e.to_string()))
    }
}

/// A safe harbor address with an activation flag. The address is mutable
/// while deactivated and frozen once activated.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct SafeHarbor {
    address: SafeHarborAddress,
    activated: bool,
}

impl SafeHarbor {
    /// Creates a new deactivated safe harbor for the given address.
    pub fn new(address: SafeHarborAddress) -> Self {
        Self {
            address,
            activated: false,
        }
    }

    /// Returns the configured safe harbor address.
    pub fn address(&self) -> &SafeHarborAddress {
        &self.address
    }

    /// Returns `Some(&address)` when activated, otherwise `None`.
    pub fn active_address(&self) -> Option<&SafeHarborAddress> {
        self.activated.then_some(&self.address)
    }

    /// Returns whether the safe harbor is currently activated.
    pub fn is_activated(&self) -> bool {
        self.activated
    }

    /// Sets the activation flag.
    pub fn set_activated(&mut self, activated: bool) {
        self.activated = activated;
    }

    /// Updates the address if the safe harbor is not currently activated.
    ///
    /// Returns `true` if the address was updated, `false` if the update was
    /// rejected because the safe harbor is already activated. The address
    /// is frozen on activation so bridge nodes always observe a single
    /// destination.
    pub fn update_address(&mut self, address: SafeHarborAddress) -> bool {
        if self.activated {
            return false;
        }
        self.address = address;
        true
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::WitnessVersion;
    use ssz::{Decode, Encode};

    use super::*;

    /// BIP-350 test vector: the P2TR address whose output key is the x-only generator
    /// point, the payload of [`p2tr_descriptor_a`].
    const P2TR_ADDRESS_A: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

    fn parse_address(address: &str) -> Address<NetworkUnchecked> {
        address.parse().expect("valid address")
    }

    fn non_p2tr_descriptor() -> Descriptor {
        Descriptor::new_p2wpkh(&[0xAA; 20])
    }

    fn p2tr_descriptor_a() -> Descriptor {
        // x-only public key for the generator point G.
        let payload = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        Descriptor::new_p2tr(&payload).expect("valid x-only public key")
    }

    fn p2tr_descriptor_b() -> Descriptor {
        // `[2u8; 32]` happens to be a valid x-only pubkey on secp256k1; see
        // the bitcoin-bosd `Descriptor::new_p2tr` doctest.
        Descriptor::new_p2tr(&[2u8; 32]).expect("valid x-only public key")
    }

    fn safe_harbor_address_a() -> SafeHarborAddress {
        SafeHarborAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted")
    }

    fn safe_harbor_address_b() -> SafeHarborAddress {
        SafeHarborAddress::try_from(p2tr_descriptor_b()).expect("p2tr accepted")
    }

    #[test]
    fn new_is_deactivated() {
        let sh = SafeHarbor::new(safe_harbor_address_a());
        assert!(!sh.is_activated());
        assert_eq!(sh.address(), &safe_harbor_address_a());
        assert_eq!(sh.active_address(), None);
    }

    #[test]
    fn set_activated_toggles_flag_and_active_address() {
        let mut sh = SafeHarbor::new(safe_harbor_address_a());

        sh.set_activated(true);
        assert!(sh.is_activated());
        assert_eq!(sh.active_address(), Some(&safe_harbor_address_a()));

        sh.set_activated(false);
        assert!(!sh.is_activated());
        assert_eq!(sh.active_address(), None);
    }

    #[test]
    fn update_address_when_deactivated_succeeds() {
        let mut sh = SafeHarbor::new(safe_harbor_address_a());
        assert!(sh.update_address(safe_harbor_address_b()));
        assert_eq!(sh.address(), &safe_harbor_address_b());
        assert!(!sh.is_activated());
    }

    #[test]
    fn update_address_when_activated_is_rejected() {
        let mut sh = SafeHarbor::new(safe_harbor_address_a());
        sh.set_activated(true);

        assert!(!sh.update_address(safe_harbor_address_b()));
        // Address must remain unchanged when the update is rejected.
        assert_eq!(sh.address(), &safe_harbor_address_a());
        assert!(sh.is_activated());
        assert_eq!(sh.active_address(), Some(&safe_harbor_address_a()));
    }

    #[test]
    fn ssz_roundtrip() {
        let mut sh = SafeHarbor::new(safe_harbor_address_a());
        sh.set_activated(true);
        let bytes = sh.as_ssz_bytes();
        let decoded = SafeHarbor::from_ssz_bytes(&bytes).expect("ssz decode");
        assert_eq!(sh, decoded);
    }

    /// The RPC `getSafeHarbor` endpoint returns `SafeHarbor` as JSON, so the
    /// serde representation must round-trip and stay in sync with what clients
    /// consume.
    #[test]
    fn json_serde_roundtrip() {
        let mut sh = SafeHarbor::new(safe_harbor_address_a());
        sh.set_activated(true);
        let json = serde_json::to_string(&sh).expect("serialize");
        let decoded: SafeHarbor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sh, decoded);
        assert!(json.contains("\"activated\":true"));
        assert!(json.contains("\"address\""));
    }

    #[test]
    fn safe_harbor_address_rejects_non_p2tr() {
        let descriptor = non_p2tr_descriptor();
        let expected_tag = descriptor.type_tag();
        let err = SafeHarborAddress::try_from(descriptor).expect_err("non-p2tr rejected");
        assert_eq!(err, NotP2trDescriptor(expected_tag));
    }

    #[test]
    fn safe_harbor_address_accepts_p2tr() {
        let addr = SafeHarborAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted");
        assert_eq!(addr.as_descriptor(), &p2tr_descriptor_a());
    }

    #[test]
    fn safe_harbor_address_ssz_roundtrip() {
        let addr = SafeHarborAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted");
        let bytes = addr.as_ssz_bytes();
        let decoded = SafeHarborAddress::from_ssz_bytes(&bytes).expect("ssz decode");
        assert_eq!(addr, decoded);
    }

    /// SSZ decoding must reject wire bytes whose inner descriptor is not P2TR,
    /// even though those bytes parse as a valid `Descriptor`.
    #[test]
    fn safe_harbor_address_ssz_rejects_non_p2tr() {
        #[derive(Encode)]
        struct NonP2tr(Descriptor);

        let bytes = NonP2tr(non_p2tr_descriptor()).as_ssz_bytes();
        let err = SafeHarborAddress::from_ssz_bytes(&bytes)
            .expect_err("non-P2TR descriptor must be rejected");
        assert!(matches!(err, ssz::DecodeError::BytesInvalid(_)));
    }

    #[test]
    fn safe_harbor_address_json_roundtrip() {
        let addr = SafeHarborAddress::try_from(p2tr_descriptor_a()).expect("p2tr accepted");
        let json = serde_json::to_string(&addr).expect("serialize");
        let decoded: SafeHarborAddress = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(addr, decoded);
    }

    /// JSON deserialization must reject a descriptor whose type is not P2TR,
    /// preserving the invariant against untrusted wire input.
    #[test]
    fn safe_harbor_address_json_rejects_non_p2tr() {
        let json = serde_json::to_string(&non_p2tr_descriptor()).expect("serialize");
        let err = serde_json::from_str::<SafeHarborAddress>(&json)
            .expect_err("non-P2TR descriptor must be rejected");
        assert!(err.to_string().contains("P2TR"));
    }

    /// Pins the address mapping to a fixed vector: the witness program is the descriptor
    /// payload, with no tweak applied in either direction.
    #[test]
    fn safe_harbor_address_matches_bip350_vector() {
        let from_address = SafeHarborAddress::try_from_address(&parse_address(P2TR_ADDRESS_A))
            .expect("p2tr address accepted");

        assert_eq!(from_address, safe_harbor_address_a());
        assert_eq!(
            safe_harbor_address_a()
                .to_address(Network::Bitcoin)
                .to_string(),
            P2TR_ADDRESS_A
        );
    }

    #[test]
    fn safe_harbor_address_ignores_the_address_network() {
        let regtest = safe_harbor_address_a().to_address(Network::Regtest);
        assert!(regtest.to_string().starts_with("bcrt1p"));

        let from_regtest = SafeHarborAddress::try_from_address(&regtest.into_unchecked())
            .expect("p2tr address accepted");
        assert_eq!(from_regtest, safe_harbor_address_a());
    }

    #[test]
    fn safe_harbor_address_rejects_non_p2tr_address() {
        // BIP-173 P2WPKH test vector.
        let address = parse_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");

        assert_eq!(
            SafeHarborAddress::try_from_address(&address),
            Err(InvalidSafeHarborAddress::NotP2tr)
        );
    }

    /// A v1 program of 32 bytes is a well-formed address whatever the bytes are, so the
    /// output key check has to happen here.
    #[test]
    fn safe_harbor_address_rejects_off_curve_output_key() {
        // Above the field prime, so not the x-coordinate of any point.
        let program =
            WitnessProgram::new(WitnessVersion::V1, &[0xFF; P2TR_LEN]).expect("32-byte v1 program");
        let address = Address::from_witness_program(program, Network::Bitcoin).into_unchecked();

        assert_eq!(
            SafeHarborAddress::try_from_address(&address),
            Err(InvalidSafeHarborAddress::InvalidOutputKey)
        );
    }

    /// The custom `Arbitrary` impl must only ever yield P2TR descriptors,
    /// since constructing a non-P2TR `SafeHarborAddress` would violate the
    /// type invariant that `new`, `Deserialize`, and `SszDecode` enforce.
    #[cfg(feature = "arbitrary")]
    #[test]
    fn safe_harbor_address_arbitrary_is_always_p2tr() {
        let seed: Vec<u8> = (0..=u8::MAX).collect();
        let mut u = arbitrary::Unstructured::new(&seed);
        let addr = SafeHarborAddress::arbitrary(&mut u).expect("arbitrary safe harbor address");
        assert_eq!(addr.as_descriptor().type_tag(), DescriptorType::P2tr);
    }
}
